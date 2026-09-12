"""Linux container runtime and workload enumeration."""

import re

from ..api import plugin, SessionContext
from ..shared.common import format_containers_report
from ..shared.runner import run_collector_plugin
from ._helpers import build_linux_collector_command

RUNTIME_CVES = {
    'runc': [
        {'cve':'CVE-2019-5736','fixed_in':(1,0,0,0),'severity':'critical',
         'title':'runc container escape via /proc/self/exe overwrite',
         'description':'Malicious container overwrites host runc binary through /proc/self/exe.',
         'exploit':'public','vector':'container_escape'},
        {'cve':'CVE-2019-19921','fixed_in':(1,0,0,0),'severity':'medium',
         'title':'runc /proc mount information leak',
         'description':'Bind-mount handling exposes /proc entries inside the container.',
         'exploit':'none','vector':'info_leak'},
        {'cve':'CVE-2021-30465','fixed_in':(1,0,0,0),'severity':'high',
         'title':'runc symlink-exchange bind mount escape',
         'description':'Race condition in mount handling allows symlink exchange to bind-mount host paths.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2022-29162','fixed_in':(1,1,2,0),'severity':'medium',
         'title':'runc incorrect default capability set',
         'description':'runc applies more default capabilities than intended in some configs.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2022-31097','fixed_in':(1,1,3,0),'severity':'medium',
         'title':'runc incorrect handling of ambient capabilities',
         'description':'Capabilities may leak outside container process tree.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2023-27561','fixed_in':(1,1,5,0),'severity':'high',
         'title':'runc /proc mount info leak (regression of CVE-2019-19921)',
         'description':'runc before 1.1.5 has a regression allowing access to /proc via bind mount.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2023-28642','fixed_in':(1,1,5,0),'severity':'medium',
         'title':'runc /proc/self/fd bypass of masked paths',
         'description':'AppArmor/SELinux can be bypassed via /proc/self/fd in some configurations.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2023-42366','fixed_in':(1,1,5,0),'severity':'medium',
         'title':'runc libseccomp-related memory issue',
         'description':'Denial of service in runc when handling crafted seccomp profiles.',
         'exploit':'none','vector':'dos'},
        {'cve':'CVE-2024-21626','fixed_in':(1,1,12,0),'severity':'critical',
         'title':'runc internal fd leak -> container escape (Leaky Vessels)',
         'description':'File descriptor leak lets a container process access host filesystem via /proc/self/fd.',
         'exploit':'public','vector':'container_escape'},
        {'cve':'CVE-2024-45310','fixed_in':(1,2,0,0),'severity':'medium',
         'title':'runc os.MkdirAll symlink attack',
         'description':'runc allows empty directory creation via symlinks, potentially crossing mount boundaries.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2025-31133','fixed_in':(1,2,8,0),'severity':'high',
         'title':'runc masked path bypass via /dev/null bind mount race',
         'description':'TOCTOU on /dev/null replacement lets container write to masked host paths.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2025-52565','fixed_in':(1,2,8,0),'severity':'high',
         'title':'runc /dev/console bind mount race',
         'description':'Race condition on /dev/console allows escape to host via crafted device.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2025-52881','fixed_in':(1,2,8,0),'severity':'high',
         'title':'runc procfs write via apparmor label race',
         'description':'AppArmor label applied too late allows writes to procfs before confinement.',
         'exploit':'poc','vector':'container_escape'},
    ],
    'crun': [
        {'cve':'CVE-2021-20222','fixed_in':(0,18,0,0),'severity':'medium',
         'title':'crun incorrect handling of user namespace',
         'description':'crun may not correctly apply user namespace isolation.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2022-27650','fixed_in':(1,4,1,0),'severity':'high',
         'title':'crun inherits cgroup/terminal state -> escape',
         'description':'crun before 1.4.1 inherits sensitive file descriptors from the parent process.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2022-0532','fixed_in':(1,4,0,0),'severity':'medium',
         'title':'crun crash on crafted image config',
         'description':'Malformed OCI config causes crun to crash.',
         'exploit':'none','vector':'dos'},
        {'cve':'CVE-2023-28118','fixed_in':(1,7,2,0),'severity':'medium',
         'title':'crun symlink handling in volumes',
         'description':'Symlink following in volume mount setup can cross container boundary.',
         'exploit':'none','vector':'container_escape'},
        {'cve':'CVE-2025-24965','fixed_in':(1,20,0,0),'severity':'high',
         'title':'crun krun handler rootfs escape via malicious image',
         'description':'A malicious container image could trick the krun handler into escaping the root filesystem, allowing file creation or modification on the host.',
         'exploit':'poc','vector':'container_escape'},
    ],
    'containerd': [
        {'cve':'CVE-2018-10892','fixed_in':(1,1,2,0),'severity':'medium',
         'title':'containerd AppArmor profile default bypass',
         'description':'Default AppArmor profile is not applied in some containerd configurations.',
         'exploit':'none','vector':'container_escape'},
        {'cve':'CVE-2020-15257','fixed_in':(1,4,3,0),'severity':'high',
         'title':'containerd-shim abstract socket -> host namespace access',
         'description':'containerd-shim exposes abstract Unix socket reachable from hostNetwork containers.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2020-15157','fixed_in':(1,4,0,0),'severity':'medium',
         'title':'containerd credential leakage via redirect',
         'description':'Credential helper output leaked when pulling from crafted registry redirect.',
         'exploit':'poc','vector':'info_leak'},
        {'cve':'CVE-2021-32760','fixed_in':(1,4,9,0),'severity':'high',
         'title':'containerd archive extraction -> file overwrite',
         'description':'Malicious image layer writes files outside target directory via crafted tar.',
         'exploit':'poc','vector':'rce'},
        {'cve':'CVE-2021-41103','fixed_in':(1,5,9,0),'severity':'medium',
         'title':'containerd insufficient path sanitization in rootfs',
         'description':'Crafted image can place symlinks that escape during extraction.',
         'exploit':'none','vector':'container_escape'},
        {'cve':'CVE-2022-23648','fixed_in':(1,6,1,0),'severity':'high',
         'title':'containerd CRI plugin host path read via crafted image',
         'description':'Crafted image config allows reading arbitrary host files.',
         'exploit':'poc','vector':'info_leak'},
        {'cve':'CVE-2024-40635','fixed_in':(1,7,14,0),'severity':'medium',
         'title':'containerd user ID overflow',
         'description':'Integer overflow in user ID handling on 32-bit platforms.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2024-25621','fixed_in':(1,7,29,0),'severity':'medium',
         'title':'containerd overly broad default permissions on CRI directories',
         'description':'Directory paths /var/lib/containerd, /run/containerd/io.containerd.grpc.v1.cri and /run/containerd/io.containerd.sandbox.controller.v1.shim were created with incorrect permissions, enabling local privilege escalation.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2025-64329','fixed_in':(1,7,29,0),'severity':'medium',
         'title':'containerd CRI Attach goroutine leak -> host memory exhaustion',
         'description':'A user can exhaust memory on the host due to goroutine leaks in the CRI Attach implementation.',
         'exploit':'none','vector':'dos'},
        {'cve':'CVE-2026-53492','fixed_in':(2,3,2,0),'severity':'critical',
         'title':'containerd CRI trusts CDI annotations from checkpoint metadata',
         'description':'Improperly trusts Container Device Interface (CDI) annotations found within untrusted checkpoint image metadata during container restoration, allowing bypass of device plugin enforcement.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2026-50195','fixed_in':(2,3,2,0),'severity':'high',
         'title':'containerd CRI fails to validate image references in checkpoint import',
         'description':'Fails to validate the image references specified within a checkpoint image’s configuration, potentially allowing unauthorized image access.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2026-53488','fixed_in':(1,7,33,0),'severity':'medium',
         'title':'containerd CRI plugin propagates labels from image to container',
         'description':'The CRI plugin propagates labels from an image to the container, which can lead to unexpected behavior.',
         'exploit':'none','vector':'info_leak'},
    ],
    'docker': [
        {'cve':'CVE-2018-15664','fixed_in':(18,9,7,0),'severity':'high',
         'title':'Docker cp TOCTOU symlink swap',
         'description':'Race lets container swap a copied path for a symlink to read/write host files.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2019-14271','fixed_in':(19,3,0,0),'severity':'high',
         'title':'Docker cp loads host libraries into container',
         'description':'docker cp with a malicious image triggers host library loading.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2019-16884','fixed_in':(19,3,0,0),'severity':'medium',
         'title':'Docker AppArmor bypass via malicious image',
         'description':'AppArmor profile not applied when using certain image entrypoints.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2020-13401','fixed_in':(19,3,0,0),'severity':'medium',
         'title':'Docker IPv6 router advertisement MITM',
         'description':'Container can spoof IPv6 RA to redirect neighbor traffic.',
         'exploit':'poc','vector':'info_leak'},
        {'cve':'CVE-2021-41091','fixed_in':(20,10,9,0),'severity':'high',
         'title':'Docker data-root permissions -> container escape',
         'description':'Malicious container can access /var/lib/docker and modify other containers.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2021-41089','fixed_in':(20,10,9,0),'severity':'medium',
         'title':'Docker cp path escape on symlinked root',
         'description':'docker cp follows symlinks in crafted image to write outside container.',
         'exploit':'none','vector':'container_escape'},
        {'cve':'CVE-2021-21284','fixed_in':(20,10,3,0),'severity':'high',
         'title':'Docker userns remap privilege escalation',
         'description':'User in a remapped container can access host files via crafted subuid ranges.',
         'exploit':'poc','vector':'privesc'},
        {'cve':'CVE-2021-21285','fixed_in':(20,10,3,0),'severity':'medium',
         'title':'Docker daemon crash on malformed image',
         'description':'Crafted image crashes dockerd causing DoS.',
         'exploit':'none','vector':'dos'},
        {'cve':'CVE-2024-29018','fixed_in':(26,0,0,0),'severity':'medium',
         'title':'Docker internal network DNS bypass',
         'description':'Containers on internal-only networks can still resolve external DNS.',
         'exploit':'none','vector':'info_leak'},
        {'cve':'CVE-2024-41110','fixed_in':(27,1,1,0),'severity':'critical',
         'title':'Docker AuthZ plugin bypass (re-emergence of 2018 bug)',
         'description':'Empty Content-Length in API request bypasses Authorization plugins -> full daemon control.',
         'exploit':'poc','vector':'privesc'},
        {'cve':'CVE-2024-36621','fixed_in':(26,0,0,0),'severity':'medium',
         'title':'Docker BuildKit arbitrary file read',
         'description':'Crafted build context allows reading files outside context.',
         'exploit':'none','vector':'info_leak'},
        {'cve':'CVE-2025-3248','fixed_in':(28,0,0,0),'severity':'critical',
         'title':'Langflow/Docker API chain (context dependent)',
         'description':'Some Docker API wrappers expose unauthenticated code paths when chained.',
         'exploit':'poc','vector':'rce'},
        {'cve':'CVE-2025-62725','fixed_in':(2,40,2,0),'severity':'medium',
         'title':'Docker Compose path traversal via remote OCI artifacts',
         'description':'Path traversal vulnerability in Docker Compose due to lack of validation of remote OCI Compose artifact setting values.',
         'exploit':'none','vector':'info_leak'},
        {'cve':'CVE-2026-33747','fixed_in':(29,1,3,0),'severity':'high',
         'title':'Docker BuildKit file path validation bypass',
         'description':'BuildKit incorrectly handled file path validation when processing frontend API messages, allowing writes outside the intended state directory.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2026-33748','fixed_in':(29,1,3,0),'severity':'high',
         'title':'Docker BuildKit Git URL subdir validation bypass',
         'description':'BuildKit incorrectly validated the subdir component of Git URL fragments, allowing access to files outside the checked-out repository root.',
         'exploit':'poc','vector':'info_leak'},
        {'cve':'CVE-2026-41567','fixed_in':(29,1,3,0),'severity':'critical',
         'title':'Docker compressed archive upload leads to RCE',
         'description':'Arbitrary code execution with full daemon privileges when a user uploads a compressed archive into a container.',
         'exploit':'poc','vector':'rce'},
        {'cve':'CVE-2026-34040','fixed_in':(28,3,0,0),'severity':'high',
         'title':'Docker AuthZ bypass via oversized HTTP request',
         'description':'Authorization bypass that silently disables security policies, enabling full host takeover.',
         'exploit':'poc','vector':'privesc'},
    ],
    'podman': [
        {'cve':'CVE-2019-10152','fixed_in':(1,3,0,0),'severity':'medium',
         'title':'Podman path traversal in volume mounts',
         'description':'Crafted symlink in volume source path escapes container root.',
         'exploit':'none','vector':'container_escape'},
        {'cve':'CVE-2020-14370','fixed_in':(2,0,2,0),'severity':'medium',
         'title':'Podman environment variable leakage',
         'description':'Env vars from one container leak to another via shared storage.',
         'exploit':'none','vector':'info_leak'},
        {'cve':'CVE-2020-1726','fixed_in':(1,6,4,0),'severity':'medium',
         'title':'Podman host path disclosure via volume',
         'description':'Race condition exposes arbitrary host paths.',
         'exploit':'none','vector':'info_leak'},
        {'cve':'CVE-2021-20199','fixed_in':(3,3,1,0),'severity':'medium',
         'title':'Podman traffic leak between containers',
         'description':'Rootless Podman containers can intercept each other via localhost.',
         'exploit':'none','vector':'info_leak'},
        {'cve':'CVE-2022-1227','fixed_in':(4,0,0,0),'severity':'high',
         'title':'Podman psgo escape via malicious container name',
         'description':'Crafted container name injects flags into psgo process listing.',
         'exploit':'poc','vector':'privesc'},
        {'cve':'CVE-2022-2989','fixed_in':(4,2,0,0),'severity':'medium',
         'title':'Podman --userns=keep-id privileges',
         'description':'keep-id mode keeps excessive privileges on host files.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2023-0778','fixed_in':(4,4,1,0),'severity':'medium',
         'title':'Podman tmpdir symlink race',
         'description':'Crafted symlink in tmpdir allows file overwrite.',
         'exploit':'none','vector':'container_escape'},
        {'cve':'CVE-2023-30571','fixed_in':(4,5,2,0),'severity':'medium',
         'title':'Podman libpod race in volume creation',
         'description':'Race in volume creation allows symlink escape.',
         'exploit':'none','vector':'container_escape'},
        {'cve':'CVE-2024-1753','fixed_in':(4,9,2,0),'severity':'high',
         'title':'Podman build --volume -> host filesystem write',
         'description':'Crafted Containerfile with --volume writes arbitrary host paths during build.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2024-9407','fixed_in':(5,3,0,0),'severity':'medium',
         'title':'Podman bind mount validation bypass',
         'description':'Insufficient validation of bind-mount sources allows escape.',
         'exploit':'none','vector':'container_escape'},
        {'cve':'CVE-2024-9675','fixed_in':(5,3,1,0),'severity':'medium',
         'title':'Podman cache path traversal',
         'description':'Crafted image name writes outside cache directory.',
         'exploit':'none','vector':'container_escape'},
        {'cve':'CVE-2024-11218','fixed_in':(5,2,2,0),'severity':'medium',
         'title':'Podman/Buildah container breakout via --jobs=2 race condition',
         'description':'A flaw in podman build and buildah allows container breakout using --jobs=2 and a race condition when building a malicious Containerfile.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2025-6032','fixed_in':(5,4,0,0),'severity':'high',
         'title':'Podman machine init missing TLS certificate validation',
         'description':'Man-in-the-middle attack due to missing TLS certificate validation when downloading VM images from OCI registry using the machine init command.',
         'exploit':'poc','vector':'info_leak'},
        {'cve':'CVE-2025-9566','fixed_in':(5,4,0,0),'severity':'medium',
         'title':'Podman kube play overwrites host files',
         'description':'An attacker may use the kube play command to overwrite host files when the kube file specifies certain configurations.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2025-52881','fixed_in':(1,2,8,0),'severity':'high',
         'title':'Podman inherits runc procfs write via apparmor label race',
         'description':'Podman inherits the runc container escape and denial of service due to arbitrary write gadgets and procfs write redirects.',
         'exploit':'poc','vector':'container_escape'},
    ],
    'crio': [
        {'cve':'CVE-2019-9946','fixed_in':(1,13,0,0),'severity':'medium',
         'title':'CRI-O IPTables rule overwrite',
         'description':'Port mapping uses replace instead of append, overwriting host rules.',
         'exploit':'none','vector':'info_leak'},
        {'cve':'CVE-2021-20291','fixed_in':(1,20,4,0),'severity':'medium',
         'title':'CRI-O image pull deadlock DoS',
         'description':'Crafted image causes CRI-O to deadlock during pull.',
         'exploit':'none','vector':'dos'},
        {'cve':'CVE-2022-0811','fixed_in':(1,24,0,0),'severity':'critical',
         'title':'CRI-O kernel parameter injection (cr8escape)',
         'description':'Crafted pod sysctl writes host kernel params -> escape.',
         'exploit':'public','vector':'container_escape'},
        {'cve':'CVE-2022-1708','fixed_in':(1,24,1,0),'severity':'high',
         'title':'CRI-O exec sync DoS',
         'description':'Malformed exec request crashes or hangs CRI-O.',
         'exploit':'none','vector':'dos'},
        {'cve':'CVE-2022-4318','fixed_in':(1,25,2,0),'severity':'medium',
         'title':'CRI-O local volume path traversal',
         'description':'Crafted local volume path escapes allowed directory.',
         'exploit':'none','vector':'container_escape'},
        {'cve':'CVE-2024-3154','fixed_in':(1,26,0,0),'severity':'high',
         'title':'CRI-O arbitrary command injection via pod annotation',
         'description':'An arbitrary systemd property can be injected via a Pod annotation, allowing any user who can create a pod with an arbitrary annotation to perform arbitrary actions on the host system.',
         'exploit':'poc','vector':'privesc'},
        {'cve':'CVE-2024-5154','fixed_in':(1,28,0,0),'severity':'high',
         'title':'CRI-O symlink traversal allows host file read/write',
         'description':'A malicious container can create a symbolic link to arbitrary files on the host via directory traversal, allowing read and write to arbitrary files.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2025-0750','fixed_in':(1,30,0,0),'severity':'medium',
         'title':'CRI-O path traversal in log management functions',
         'description':'A path traversal issue in UnMountPodLogs and LinkContainerLogs may allow an attacker with permissions to create and delete Pods to unmount arbitrary host paths, leading to node-level denial of service.',
         'exploit':'none','vector':'dos'},
        {'cve':'CVE-2025-4437','fixed_in':(1,31,0,0),'severity':'medium',
         'title':'CRI-O memory exhaustion via large /etc/passwd',
         'description':'When a container specifies a non-existent user in securityContext.runAsUser, CRI-O attempts to create the user and loads the entire /etc/passwd file into memory, potentially causing memory exhaustion.',
         'exploit':'none','vector':'dos'},
        {'cve':'CVE-2025-58058','fixed_in':(1,22,3,0),'severity':'medium',
         'title':'CRI-O unspecified vulnerability (see vendor advisory)',
         'description':'A vulnerability affecting CRI-O versions less than 1.22.3-16. Refer to the vendor advisory for details.',
         'exploit':'none','vector':'unknown'},
    ],
    'kubernetes': [
        {'cve':'CVE-2018-1002105','fixed_in':(1,12,0,0),'severity':'critical',
         'title':'Kubernetes API server privilege escalation',
         'description':'Crafted request upgrades connection through API server to backend -> cluster admin.',
         'exploit':'public','vector':'privesc'},
        {'cve':'CVE-2019-11246','fixed_in':(1,15,0,0),'severity':'medium',
         'title':'kubectl cp path traversal',
         'description':'Crafted tar in kubectl cp writes outside target directory.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2019-11253','fixed_in':(1,16,0,0),'severity':'high',
         'title':'Kubernetes YAML bomb (billion laughs)',
         'description':'Malicious YAML in API request causes API server DoS.',
         'exploit':'poc','vector':'dos'},
        {'cve':'CVE-2019-11248','fixed_in':(1,16,0,0),'severity':'medium',
         'title':'Kubernetes /debug/pprof exposure',
         'description':'Kubelet exposes pprof endpoint without auth on some builds.',
         'exploit':'none','vector':'info_leak'},
        {'cve':'CVE-2019-11247','fixed_in':(1,16,0,0),'severity':'high',
         'title':'Kubernetes API server RBAC bypass',
         'description':'Cluster-scoped resource accessed via namespaced path.',
         'exploit':'poc','vector':'privesc'},
        {'cve':'CVE-2020-8554','fixed_in':(1,20,0,0),'severity':'medium',
         'title':'Kubernetes MITM via ExternalIP service',
         'description':'Any user able to create a Service can hijack external IPs.',
         'exploit':'poc','vector':'privesc'},
        {'cve':'CVE-2020-8558','fixed_in':(1,19,0,0),'severity':'medium',
         'title':'Kubernetes kube-proxy localhost bypass',
         'description':'Containers can reach host localhost services via crafted routes.',
         'exploit':'poc','vector':'privesc'},
        {'cve':'CVE-2020-8559','fixed_in':(1,19,0,0),'severity':'high',
         'title':'Kubernetes kubelet privilege escalation via redirect',
         'description':'Compromised node can redirect API calls to other nodes.',
         'exploit':'poc','vector':'privesc'},
        {'cve':'CVE-2021-25741','fixed_in':(1,22,0,0),'severity':'high',
         'title':'Kubernetes subPath symlink -> host file access',
         'description':'Symlink in subPath volumeMount exposes host filesystem.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2021-25735','fixed_in':(1,22,0,0),'severity':'medium',
         'title':'Kubernetes ValidatingAdmissionWebhook bypass',
         'description':'Race condition in webhook allows bypass.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2021-25737','fixed_in':(1,22,0,0),'severity':'medium',
         'title':'Kubernetes hostNetwork pod endpoint hijack',
         'description':'Crafted endpoint slice redirects cluster traffic.',
         'exploit':'none','vector':'info_leak'},
        {'cve':'CVE-2022-3172','fixed_in':(1,25,0,0),'severity':'medium',
         'title':'Kubernetes aggregated API server SSRF',
         'description':'Crafted APIService redirects API server traffic.',
         'exploit':'poc','vector':'privesc'},
        {'cve':'CVE-2022-3294','fixed_in':(1,25,4,0),'severity':'medium',
         'title':'Kubernetes node address validation bypass',
         'description':'Crafted Node object misdirects kubelet traffic.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2023-2727','fixed_in':(1,27,0,0),'severity':'medium',
         'title':'Kubernetes kube-apiserver image policy bypass',
         'description':'ImagePolicyWebhook bypass via crafted pod spec.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2023-2728','fixed_in':(1,27,0,0),'severity':'medium',
         'title':'Kubernetes service account token bypass',
         'description':'Crafted pod mounts projected SA token despite admission policy.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2023-3676','fixed_in':(1,28,0,0),'severity':'high',
         'title':'Kubernetes kubelet subPath injection via Windows node',
         'description':'Injection in subPath allows command execution on Windows nodes.',
         'exploit':'poc','vector':'rce'},
        {'cve':'CVE-2023-3955','fixed_in':(1,28,0,0),'severity':'high',
         'title':'Kubernetes kubelet subPath injection (Linux)',
         'description':'Injection in subPath allows command execution on Linux nodes.',
         'exploit':'poc','vector':'rce'},
        {'cve':'CVE-2023-5528','fixed_in':(1,28,4,0),'severity':'high',
         'title':'Kubernetes in-tree storage plugin privesc (Windows)',
         'description':'Crafted pod spec with volumeMount subPath escapes to node.',
         'exploit':'poc','vector':'privesc'},
        {'cve':'CVE-2024-3177','fixed_in':(1,30,0,0),'severity':'medium',
         'title':'Kubernetes envFrom secrets bypass',
         'description':'envFrom bypasses admission controls on secret references.',
         'exploit':'none','vector':'info_leak'},
        {'cve':'CVE-2024-7598','fixed_in':(1,28,9,0),'severity':'medium',
         'title':'Kubernetes network policy bypass during namespace deletion',
         'description':'A malicious or compromised pod could bypass network restrictions enforced by network policies during namespace deletion due to undefined deletion order.',
         'exploit':'poc','vector':'info_leak'},
        {'cve':'CVE-2024-10220','fixed_in':(1,28,0,0),'severity':'high',
         'title':'Kubernetes kubelet arbitrary command execution via gitRepo volumes',
         'description':'The Kubernetes kubelet component allows arbitrary command execution via specially crafted gitRepo volumes.',
         'exploit':'poc','vector':'rce'},
        {'cve':'CVE-2025-1097','fixed_in':(1,32,0,0),'severity':'critical',
         'title':'Kubernetes Ingress-NGINX controller RCE',
         'description':'Critical Remote Code Execution vulnerability in the Ingress-NGINX Controller for Kubernetes, exploitable to gain full cluster access.',
         'exploit':'poc','vector':'rce'},
        {'cve':'CVE-2025-1974','fixed_in':(1,32,0,0),'severity':'critical',
         'title':'Kubernetes Ingress-NGINX controller unauthenticated RCE',
         'description':'An unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller.',
         'exploit':'poc','vector':'rce'},
        {'cve':'CVE-2025-5187','fixed_in':(1,33,0,0),'severity':'medium',
         'title':'Kubernetes NodeRestriction admission controller bypass',
         'description':'Node users can delete their corresponding node object by patching themselves with an OwnerReference to a cluster-scoped resource.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2026-56852','fixed_in':(1,36,2,0),'severity':'high',
         'title':'Kubernetes unspecified vulnerability (see vendor advisory)',
         'description':'A vulnerability in Kubernetes 1.36 fixed in 1.36.2. Refer to the vendor advisory for details.',
         'exploit':'none','vector':'unknown'},
    ],
    'lxd': [
        {'cve':'CVE-2017-18641','fixed_in':(3,0,0,0),'severity':'high',
         'title':'LXD container to host escape (legacy)',
         'description':'Older LXD allowed unprivileged containers to reach host paths.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2018-10892','fixed_in':(3,3,0,0),'severity':'medium',
         'title':'LXD AppArmor profile bypass',
         'description':'Default AppArmor profile not applied consistently.',
         'exploit':'none','vector':'container_escape'},
        {'cve':'CVE-2019-10144','fixed_in':(3,13,0,0),'severity':'high',
         'title':'LXD unprivileged container -> host access',
         'description':'Unprivileged LXD container accesses host files via /proc.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2020-14362','fixed_in':(4,0,4,0),'severity':'medium',
         'title':'LXD X-Forwarded-For authentication bypass',
         'description':'Spoofed header bypasses trusted proxy checks.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2020-1738','fixed_in':(4,0,0,0),'severity':'medium',
         'title':'LXD container environment leak',
         'description':'Environment of one container visible to another via shared state.',
         'exploit':'none','vector':'info_leak'},
        {'cve':'CVE-2022-30053','fixed_in':(5,0,0,0),'severity':'medium',
         'title':'LXD REST API race condition',
         'description':'Race in API allows unauthorized operation.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2023-3757','fixed_in':(5,15,0,0),'severity':'medium',
         'title':'LXD AppArmor profile bypass',
         'description':'Malicious instance profile escapes AppArmor confinement.',
         'exploit':'none','vector':'container_escape'},
        {'cve':'CVE-2023-6597','fixed_in':(5,19,0,0),'severity':'medium',
         'title':'LXD tmpdir symlink race',
         'description':'Symlink swap in temporary directory allows file overwrite.',
         'exploit':'none','vector':'container_escape'},
        {'cve':'CVE-2024-6156','fixed_in':(5,21,2,0),'severity':'medium',
         'title':'LXD PKI mode bypass via trusted client certificate',
         'description':'LXD PKI mode can be bypassed if the client’s certificate is present in the trust store.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2024-6219','fixed_in':(5,21,1,0),'severity':'medium',
         'title':'LXD restricted certificate restrictions not honoured',
         'description':'A restricted certificate could be added to the trust store with its restrictions not honoured.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2025-54293','fixed_in':(5,21,4,0),'severity':'medium',
         'title':'LXD path traversal in log file retrieval',
         'description':'Path Traversal in the log file retrieval function in Canonical LXD 5.0 LTS allows authenticated remote attackers to read arbitrary files on the host system via crafted log file names or symbolic links.',
         'exploit':'poc','vector':'info_leak'},
        {'cve':'CVE-2025-54289','fixed_in':(6,5,0,0),'severity':'high',
         'title':'LXD privilege escalation via WebSocket connection hijacking',
         'description':'Privilege Escalation in operations API in Canonical LXD <6.5 allows attacker with read permissions to hijack terminal or console sessions and execute arbitrary commands via WebSocket connection hijacking.',
         'exploit':'poc','vector':'privesc'},
        {'cve':'CVE-2025-54287','fixed_in':(6,5,0,0),'severity':'medium',
         'title':'LXD template injection in instance snapshot creation',
         'description':'Template Injection in instance snapshot creation component in Canonical LXD (>= 4.0) allows an attacker with instance configuration permissions to read arbitrary files on the host system via specially crafted snapshot pattern templates.',
         'exploit':'poc','vector':'info_leak'},
    ],
    'lxc': [
        {'cve':'CVE-2018-6556','fixed_in':(3,0,0,0),'severity':'medium',
         'title':'LXC attach command path injection',
         'description':'Crafted container name injects into lxc-attach path.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2019-19921','fixed_in':(3,2,0,0),'severity':'medium',
         'title':'LXC /proc mount info leak',
         'description':'Proc entries exposed inside unprivileged containers.',
         'exploit':'none','vector':'info_leak'},
        {'cve':'CVE-2022-47941','fixed_in':(4,0,0,0),'severity':'medium',
         'title':'LXC dhcp denial of service',
         'description':'lxc-dhcp can be crashed with crafted packet.',
         'exploit':'none','vector':'dos'},
        {'cve':'CVE-2022-47942','fixed_in':(4,0,0,0),'severity':'medium',
         'title':'LXC directory traversal in template handling',
         'description':'Crafted template path escapes target directory.',
         'exploit':'none','vector':'container_escape'},
    ],
    'nerdctl': [
        {'cve':'CVE-2022-31097','fixed_in':(0,20,0,0),'severity':'medium',
         'title':'nerdctl inherits containerd capability leak',
         'description':'Ambient capability leak from underlying containerd.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2023-27561','fixed_in':(1,2,0,0),'severity':'medium',
         'title':'nerdctl inherits runc /proc leak',
         'description':'Exposure via underlying runc version.',
         'exploit':'poc','vector':'container_escape'},
        {'cve':'CVE-2024-40635','fixed_in':(2,0,0,0),'severity':'medium',
         'title':'nerdctl inherits containerd user-ID overflow',
         'description':'Inherits containerd issue on 32-bit platforms.',
         'exploit':'none','vector':'privesc'},
        {'cve':'CVE-2024-10846','fixed_in':(2,1,5,0),'severity':'medium',
         'title':'nerdctl compose-go excessive memory and CPU consumption',
         'description':'The compose-go library allows an authorized user who sends malicious YAML payloads to cause excessive memory and CPU cycle consumption while parsing YAML.',
         'exploit':'none','vector':'dos'},
        {'cve':'CVE-2025-58185','fixed_in':(2,1,6,0),'severity':'medium',
         'title':'nerdctl memory exhaustion via malicious DER payload',
         'description':'Parsing a maliciously crafted DER payload could allocate large amounts of memory, causing memory exhaustion.',
         'exploit':'none','vector':'dos'},
        {'cve':'CVE-2025-11065','fixed_in':(2,1,5,0),'severity':'medium',
         'title':'nerdctl sensitive information leak in logs',
         'description':'go-viper’s mapstructure may leak sensitive information in logs when processing malformed data.',
         'exploit':'none','vector':'info_leak'},
    ],
}

_SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


def _parse_version(raw):
    if not raw:
        return None
    m = re.search(r'(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?', str(raw))
    if not m:
        return None
    parts = [int(x) if x else 0 for x in m.groups()]
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts)


def _cves_for(runtime_name, version_str):
    db = RUNTIME_CVES.get(runtime_name)
    if not db:
        return []
    cur = _parse_version(version_str)
    if cur is None:
        return []
    hits = []
    for entry in db:
        fixed = entry.get('fixed_in')
        if fixed is None:
            continue
        if cur < tuple(fixed):
            hits.append(entry)
    return hits


def _analyze_runtime_versions(collected):
    collected = collected or {}
    runtimes = collected.get('runtimes') or {}
    findings = []
    per_runtime = {}

    for name, info in runtimes.items():
        info = info if isinstance(info, dict) else {}
        installed = bool(info.get('installed'))
        version = (info.get('version') or '').strip()

        if not installed or not version or version == 'N/A':
            per_runtime[name] = {'version': 'N/A', 'vulnerable': False, 'count': 0}
            continue

        hits = _cves_for(name, version)
        per_runtime[name] = {
            'version': version,
            'vulnerable': bool(hits),
            'count': len(hits),
        }
        for h in hits:
            findings.append({
                'runtime': name,
                'version': version,
                'cve': h.get('cve'),
                'severity': (h.get('severity') or '').lower(),
                'title': h.get('title'),
                'description': h.get('description'),
                'vector': h.get('vector'),
                'exploit': h.get('exploit'),
                'fixed_in': '.'.join(str(x) for x in h.get('fixed_in', ())),
            })

    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.get('severity', ''), 99))
    return {
        'runtimes': per_runtime,
        'findings': findings,
        'total': len(findings),
    }

def _collector_source():
    return r'''
import json, os, stat, subprocess

def sh(cmd, timeout=12):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

def which(name):
    return bool(sh(f'command -v {name} 2>/dev/null').strip())

def lines(cmd, limit=40, timeout=12):
    return [l.strip() for l in sh(cmd, timeout).splitlines() if l.strip()][:limit]

def tab_rows(cmd, fields, limit=50, timeout=12):
    rows = []
    for line in lines(cmd, limit, timeout):
        parts = line.split('\t')
        if not parts or not parts[0]:
            continue
        row = {}
        for i, key in enumerate(fields):
            row[key] = parts[i] if i < len(parts) else ''
        rows.append(row)
    return rows

def socket_info(path):
    info = {'path': path, 'exists': os.path.exists(path)}
    if not info['exists']:
        return info
    try:
        st = os.stat(path)
        info['mode'] = oct(st.st_mode)[-4:]
        info['socket'] = stat.S_ISSOCK(st.st_mode)
    except Exception:
        pass
    return info

def try_json(cmd, timeout=10):
    raw = sh(cmd, timeout).strip()
    if not raw or raw[0] not in '[{':
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None

def add_runtime(result, name, meta):
    if meta:
        result['runtimes'][name] = meta
        if name not in result['detected_runtimes']:
            result['detected_runtimes'].append(name)

result = {
    'summary': {},
    'detected_runtimes': [],
    'runtime_sockets': [],
    'runtimes': {},
    'containers': [],
    'images': [],
    'networks': [],
    'volumes': [],
    'pods': [],
    'compose_projects': [],
    'kubernetes': {},
    'systemd_units': [],
    'container_processes': [],
}


for path in (
    '/var/run/docker.sock', '/run/docker.sock',
    '/run/podman/podman.sock', '/var/run/podman/podman.sock',
    '/run/containerd/containerd.sock', '/var/run/containerd/containerd.sock',
    '/var/run/crio/crio.sock', '/run/crio/crio.sock',
    '/dev/lxd/sock',
):
    info = socket_info(path)
    if info.get('exists'):
        result['runtime_sockets'].append(info)

for path, label in (
    ('/var/lib/docker', 'docker'),
    ('/var/lib/containerd', 'containerd'),
    ('/var/lib/kubelet', 'kubelet'),
    ('/var/lib/rancher/k3s', 'k3s'),
    ('/var/snap/microk8s', 'microk8s'),
):
    if os.path.isdir(path):
        try:
            count = len(os.listdir(path))
        except Exception:
            count = 'N/A'
        result['runtimes'].setdefault('data_dirs', []).append({'runtime': label, 'path': path, 'entries': count})

for line in lines('systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null | grep -Ei "docker|container|kube|crio|podman|lxd|containerd" | head -25', 25, 8):
    parts = line.split(None, 4)
    if parts:
        result['systemd_units'].append({
            'unit': parts[0],
            'load': parts[1] if len(parts) > 1 else '',
            'active': parts[2] if len(parts) > 2 else '',
            'sub': parts[3] if len(parts) > 3 else '',
            'desc': parts[4][:100] if len(parts) > 4 else '',
        })

for line in lines('ps aux 2>/dev/null | grep -E "dockerd|containerd|kubelet|crio|podman|lxc|k3s" | grep -v grep | head -20', 20, 8):
    parts = line.split(None, 10)
    if len(parts) >= 11:
        result['container_processes'].append({'user': parts[0], 'pid': parts[1], 'cmd': parts[10][:140]})

if which('docker'):
    meta = {
        'version': sh('docker version --format "{{.Server.Version}}" 2>/dev/null').strip() or sh('docker --version 2>/dev/null').strip(),
        'client': sh('docker version --format "{{.Client.Version}}" 2>/dev/null').strip(),
        'rootless': sh('docker info --format "{{.SecurityOptions}}" 2>/dev/null').strip(),
        'storage_driver': sh('docker info --format "{{.Driver}}" 2>/dev/null').strip(),
        'cgroup_driver': sh('docker info --format "{{.CgroupDriver}}" 2>/dev/null').strip(),
        'runtimes': sh('docker info --format "{{.Runtimes}}" 2>/dev/null').strip()[:200],
        'swarm': sh('docker info --format "{{.Swarm.LocalNodeState}}" 2>/dev/null').strip(),
        'service': sh('systemctl is-active docker 2>/dev/null').strip(),
    }
    add_runtime(result, 'docker', meta)
    for row in tab_rows(
        'docker ps -a --no-trunc --format "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.State}}\t{{.Ports}}\t{{.RunningFor}}\t{{.Labels}}"',
        ['id', 'name', 'image', 'status', 'state', 'ports', 'running_for', 'labels'], 60, 15,
    ):
        row['runtime'] = 'docker'
        result['containers'].append(row)
    for row in tab_rows(
        'docker images -a --format "{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedSince}}"',
        ['repository', 'tag', 'id', 'size', 'created'], 50, 12,
    ):
        row['runtime'] = 'docker'
        row['name'] = (row.get('repository', '') + ':' + row.get('tag', '')).strip(':')
        result['images'].append(row)
    for row in tab_rows(
        'docker network ls --format "{{.ID}}\t{{.Name}}\t{{.Driver}}\t{{.Scope}}"',
        ['id', 'name', 'driver', 'scope'], 30, 8,
    ):
        row['runtime'] = 'docker'
        result['networks'].append(row)
    for row in tab_rows(
        'docker volume ls --format "{{.Name}}\t{{.Driver}}"',
        ['name', 'driver'], 30, 8,
    ):
        row['runtime'] = 'docker'
        result['volumes'].append(row)
    compose = try_json('docker compose ls -a --format json 2>/dev/null', 10)
    if compose:
        for item in compose[:20]:
            if isinstance(item, dict):
                item['runtime'] = 'docker'
                result['compose_projects'].append(item)
    else:
        for line in lines('docker compose ls -a 2>/dev/null || docker-compose ls 2>/dev/null', 20, 10):
            result['compose_projects'].append({'runtime': 'docker', 'line': line})
    stacks = lines('docker stack ls 2>/dev/null', 15, 8)
    if stacks:
        result['runtimes']['docker']['stacks'] = stacks

if which('podman'):
    meta = {
        'version': sh('podman --version 2>/dev/null').strip(),
        'rootless': sh('podman info --format "{{.Host.Security.Rootless}}" 2>/dev/null').strip(),
        'graph_driver': sh('podman info --format "{{.Store.GraphDriverName}}" 2>/dev/null').strip(),
        'service': sh('systemctl is-active podman 2>/dev/null').strip(),
    }
    add_runtime(result, 'podman', meta)
    for row in tab_rows(
        'podman ps -a --format "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.State}}\t{{.Ports}}\t{{.Labels}}"',
        ['id', 'name', 'image', 'status', 'state', 'ports', 'labels'], 50, 12,
    ):
        row['runtime'] = 'podman'
        result['containers'].append(row)
    for row in tab_rows(
        'podman pod ps -a --format "{{.ID}}\t{{.Name}}\t{{.Status}}\t{{.Containers}}"',
        ['id', 'name', 'status', 'containers'], 25, 10,
    ):
        row['runtime'] = 'podman'
        result['pods'].append(row)
    for row in tab_rows(
        'podman images -a --format "{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}"',
        ['repository', 'tag', 'id', 'size'], 40, 10,
    ):
        row['runtime'] = 'podman'
        row['name'] = (row.get('repository', '') + ':' + row.get('tag', '')).strip(':')
        result['images'].append(row)
    for row in tab_rows(
        'podman network ls --format "{{.Name}}\t{{.Driver}}"',
        ['name', 'driver'], 25, 8,
    ):
        row['runtime'] = 'podman'
        result['networks'].append(row)
    for row in tab_rows(
        'podman volume ls --format "{{.Name}}\t{{.Driver}}"',
        ['name', 'driver'], 25, 8,
    ):
        row['runtime'] = 'podman'
        result['volumes'].append(row)

if which('nerdctl'):
    meta = {'version': sh('nerdctl --version 2>/dev/null').strip()}
    add_runtime(result, 'nerdctl', meta)
    for row in tab_rows(
        'nerdctl ps -a --format "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"',
        ['id', 'name', 'image', 'status', 'ports'], 40, 12,
    ):
        row['runtime'] = 'nerdctl'
        result['containers'].append(row)

if which('crictl'):
    meta = {
        'version': sh('crictl --version 2>/dev/null').strip(),
        'runtime_endpoint': sh('crictl config runtime-endpoint 2>/dev/null || grep runtime-endpoint /etc/crictl.yaml 2>/dev/null | head -1').strip(),
    }
    add_runtime(result, 'crictl', meta)
    pods_json = try_json('crictl pods -o json 2>/dev/null', 10)
    if pods_json and isinstance(pods_json, dict) and pods_json.get('items'):
        for item in pods_json['items'][:30]:
            meta = item.get('metadata') or {}
            status = item.get('status') or {}
            result['pods'].append({
                'runtime': 'crictl',
                'id': meta.get('id', '')[:16],
                'name': meta.get('name', ''),
                'namespace': meta.get('namespace', ''),
                'state': status.get('state', ''),
            })
    else:
        for line in lines('crictl pods 2>/dev/null', 30, 10):
            if line.lower().startswith('pod'):
                continue
            result['pods'].append({'runtime': 'crictl', 'line': line})
    ctr_json = try_json('crictl ps -a -o json 2>/dev/null', 10)
    if ctr_json and isinstance(ctr_json, dict) and ctr_json.get('containers'):
        for item in ctr_json['containers'][:40]:
            meta = item.get('metadata') or {}
            status = item.get('status') or {}
            result['containers'].append({
                'runtime': 'crictl',
                'id': meta.get('id', '')[:16],
                'name': meta.get('name', ''),
                'image': status.get('image', {}).get('image', '') if isinstance(status.get('image'), dict) else '',
                'state': status.get('state', ''),
            })
    else:
        for line in lines('crictl ps -a 2>/dev/null', 35, 10):
            if line.lower().startswith('container'):
                continue
            result['containers'].append({'runtime': 'crictl', 'line': line})
    img_json = try_json('crictl images -o json 2>/dev/null', 10)
    if img_json and isinstance(img_json, dict) and img_json.get('images'):
        for item in img_json['images'][:35]:
            spec = item.get('status') or {}
            result['images'].append({
                'runtime': 'crictl',
                'id': (item.get('id') or '')[:16],
                'name': spec.get('id', ''),
                'size': spec.get('size', ''),
            })
    else:
        for line in lines('crictl images 2>/dev/null', 30, 10):
            if line.lower().startswith('image'):
                continue
            result['images'].append({'runtime': 'crictl', 'line': line})

if which('ctr'):
    meta = {'version': sh('ctr version 2>/dev/null').strip()}
    add_runtime(result, 'containerd', meta)
    namespaces = [n.strip() for n in lines('ctr namespaces list -q 2>/dev/null', 10, 8) if n.strip()]
    if namespaces:
        meta['namespaces'] = namespaces[:10]
    ctr_containers = []
    for ns in namespaces[:5]:
        for line in lines(f'ctr -n {ns} containers list 2>/dev/null', 20, 8):
            if line.strip():
                ctr_containers.append({'namespace': ns, 'line': line.strip()[:180]})
    if ctr_containers:
        result['runtimes']['containerd']['containers'] = ctr_containers[:40]
    ctr_images = []
    for ns in namespaces[:5]:
        for line in lines(f'ctr -n {ns} images list 2>/dev/null', 15, 8):
            if line.strip():
                ctr_images.append({'namespace': ns, 'line': line.strip()[:180]})
    if ctr_images:
        result['runtimes']['containerd']['images'] = ctr_images[:30]

if which('crio') or os.path.exists('/var/run/crio/crio.sock') or os.path.exists('/run/crio/crio.sock'):
    meta = {'version': sh('crio --version 2>/dev/null || crio version 2>/dev/null').strip()}
    meta['status'] = sh('crio-status info 2>/dev/null || crictl info 2>/dev/null | head -20').strip()[:500]
    add_runtime(result, 'crio', meta)

if which('lxc-ls'):
    add_runtime(result, 'lxc', {'containers': lines('lxc-ls -f -1 2>/dev/null || lxc-ls -1 2>/dev/null', 30, 8)})
if which('lxc'):
    lxd = {
        'version': sh('lxc --version 2>/dev/null').strip(),
        'list': lines('lxc list -c ns4S6t --format csv 2>/dev/null', 30, 10),
        'profiles': lines('lxc profile list --format csv -c n,d 2>/dev/null', 20, 8),
        'networks': lines('lxc network list --format csv -c n,t,b 2>/dev/null', 20, 8),
    }
    add_runtime(result, 'lxd', lxd)

if which('machinectl'):
    machines = lines('machinectl list --no-legend --no-pager 2>/dev/null', 25, 8)
    if machines:
        add_runtime(result, 'systemd_nspawn', {'machines': machines})

k8s = {}
if which('kubectl'):
    k8s['client_version'] = sh('kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null').strip()
    k8s['context'] = sh('kubectl config current-context 2>/dev/null').strip()
    k8s['cluster'] = sh('kubectl config view --minify -o jsonpath="{.clusters[0].name}" 2>/dev/null').strip()
    k8s['api_server'] = sh('kubectl cluster-info 2>/dev/null | head -3').strip()
    k8s['nodes'] = lines('kubectl get nodes -o wide --no-headers 2>/dev/null', 20, 12)
    k8s['namespaces'] = lines('kubectl get ns --no-headers 2>/dev/null', 25, 10)
    k8s['pods'] = lines('kubectl get pods -A -o wide --no-headers 2>/dev/null', 50, 15)
    k8s['deployments'] = lines('kubectl get deploy -A --no-headers 2>/dev/null', 30, 10)
    k8s['services'] = lines('kubectl get svc -A --no-headers 2>/dev/null', 30, 10)
    k8s['daemonsets'] = lines('kubectl get ds -A --no-headers 2>/dev/null', 20, 10)
    add_runtime(result, 'kubectl', {'available': 'yes'})
if which('helm'):
    k8s['helm_releases'] = lines('helm list -A --no-headers 2>/dev/null', 25, 10)
if os.path.isdir('/var/lib/rancher/k3s') or which('k3s'):
    k8s['k3s'] = sh('k3s --version 2>/dev/null; systemctl is-active k3s 2>/dev/null').strip()
if which('microk8s'):
    k8s['microk8s'] = sh('microk8s status --format short 2>/dev/null || microk8s status 2>/dev/null | head -15').strip()
sa_base = '/var/run/secrets/kubernetes.io/serviceaccount'
if os.path.isdir(sa_base):
    k8s['in_cluster'] = {
        'namespace': sh(f'cat {sa_base}/namespace 2>/dev/null').strip(),
        'token_present': os.path.isfile(os.path.join(sa_base, 'token')),
        'ca_present': os.path.isfile(os.path.join(sa_base, 'ca.crt')),
    }
if k8s:
    result['kubernetes'] = k8s
    if 'kubectl' not in result['detected_runtimes'] and (which('kubectl') or k8s.get('in_cluster')):
        result['detected_runtimes'].append('kubernetes')

postex = {
    'current_user': {},
    'groups': {'high_value_membership': [], 'all': []},
    'socket_access': [],
    'inside_container': {},
    'privileges': {},
    'interesting_mounts': [],
    'credential_files': [],
    'container_breakout_indicators': [],
}

try:
    import pwd as _pwd, grp as _grp
    uid = os.getuid(); gid = os.getgid()
    euid = os.geteuid(); egid = os.getegid()
    user = {'uid': uid, 'gid': gid, 'euid': euid, 'egid': egid,
            'is_root': (uid == 0), 'is_euid_root': (euid == 0)}
    try:
        pw = _pwd.getpwuid(uid)
        user['username'] = pw.pw_name
        user['home'] = pw.pw_dir
        user['shell'] = pw.pw_shell
    except Exception:
        user['username'] = str(uid)
    groups = []
    try:
        for g in os.getgroups():
            name = ''
            try:
                name = _grp.getgrgid(g).gr_name
            except Exception:
                pass
            groups.append({'gid': g, 'name': name})
    except Exception:
        pass
    postex['current_user'] = user
    postex['groups']['all'] = groups
except Exception as e:
    postex['current_user'] = {'error': str(e)}

HIGH_VALUE_GROUPS = {
    'docker': 'docker group -> docker run -v /:/host ... = root',
    'lxd': 'lxd group -> privileged container w/ host mount = root',
    'lxc': 'lxc group -> container escape primitives',
    'podman': 'podman group -> privileged runtime operations',
    'disk': 'disk group -> raw disk read/write = root',
    'adm': 'adm group -> read logs / secrets',
    'sudo': 'sudo group',
    'wheel': 'wheel group (sudo)',
    'shadow': 'shadow group -> read /etc/shadow',
    'video': 'video group -> framebuffer/input access',
    'systemd-journal': 'journal access -> secrets in logs',
    'kvm': 'kvm group -> VM escape potential',
}
for g in postex['groups']['all']:
    gname = (g.get('name') or '').lower()
    if gname in HIGH_VALUE_GROUPS:
        postex['groups']['high_value_membership'].append({
            'group': gname,
            'reason': HIGH_VALUE_GROUPS[gname],
        })
        postex['container_breakout_indicators'].append(
            f'current user in group {gname}: {HIGH_VALUE_GROUPS[gname]}'
        )

def _sock_access(path):
    info = {'path': path, 'exists': os.path.exists(path)}
    if not info['exists']:
        return info
    try:
        st = os.stat(path)
        info['mode'] = oct(st.st_mode)[-4:]
        info['readable'] = os.access(path, os.R_OK)
        info['writable'] = os.access(path, os.W_OK)
        try:
            import pwd as _p, grp as _g
            info['owner'] = _p.getpwuid(st.st_uid).pw_name
            info['group'] = _g.getgrgid(st.st_gid).gr_name
        except Exception:
            info['owner'] = st.st_uid
            info['group'] = st.st_gid
    except Exception:
        pass
    return info

for _p in (
    '/var/run/docker.sock', '/run/docker.sock',
    '/run/podman/podman.sock', '/var/run/podman/podman.sock',
    '/run/containerd/containerd.sock', '/var/run/containerd/containerd.sock',
    '/var/run/crio/crio.sock', '/run/crio/crio.sock',
    '/var/snap/lxd/common/lxd/unix.socket',
    '/var/lib/lxd/unix.socket', '/var/run/lxd.sock',
    '/dev/lxd/sock',
):
    a = _sock_access(_p)
    if a.get('exists'):
        postex['socket_access'].append(a)
        if a.get('writable'):
            postex['container_breakout_indicators'].append(
                f'writable runtime socket: {_p} -> full runtime control'
            )

_ic = {}
_ic['dockerenv'] = os.path.exists('/.dockerenv')
_ic['containerenv'] = os.path.exists('/run/.containerenv')
try:
    with open('/proc/1/cgroup') as f:
        _cg = f.read().lower()
    _ic['cgroup_hints'] = [k for k in ('docker','kubepods','containerd','lxc','podman','buildkit')
                           if k in _cg]
except Exception:
    pass
try:
    with open('/proc/self/mountinfo') as f:
        _mi = f.read().lower()
    _ic['mount_hints'] = [k for k in ('docker','overlay','containerd','kube','lxcfs')
                          if k in _mi]
except Exception:
    pass
_env_hints = [k for k in ('container','KUBERNETES_SERVICE_HOST','KUBERNETES_PORT',
                          'DOCKER_CONTAINER','PODMAN','KUBERNETES_SERVICE_PORT')
              if os.environ.get(k)]
if _env_hints:
    _ic['env_hints'] = _env_hints
postex['inside_container'] = _ic


_priv = {}
try:
    with open('/proc/self/status') as f:
        for line in f:
            k, _, v = line.partition(':')
            k = k.strip(); v = v.strip()
            if k in ('CapEff','CapPrm','CapBnd','CapAmb','Seccomp','NoNewPrivs','Uid','Gid'):
                _priv[k] = v
except Exception:
    pass
if _priv.get('CapEff'):
    try:
        _caps = int(_priv['CapEff'], 16)
        if _caps == 0:
            _priv['cap_level'] = 'none'
        elif _caps >= (1 << 40):
            _priv['cap_level'] = 'likely_privileged'
        else:
            _priv['cap_level'] = 'partial'
    except Exception:
        pass
postex['privileges'] = _priv

_interesting = []
try:
    with open('/proc/self/mountinfo') as f:
        for line in f:
            parts = line.split()
            if len(parts) < 5:
                continue
            mp = parts[4]
            fstype = ''
            try:
                sep = parts.index('-')
                if len(parts) > sep + 1:
                    fstype = parts[sep + 1]
            except Exception:
                pass
            if any(k in mp for k in (
                '/var/run/docker.sock', '/run/docker.sock',
                '/var/lib/docker', '/var/lib/kubelet',
                '/var/lib/containerd', '/etc/kubernetes',
                '/host', '/mnt/host', '/var/run/secrets', '/run/secrets',
                '/var/run/containerd',
            )):
                _interesting.append({
                    'mount_point': mp,
                    'fstype': fstype,
                    'options': (parts[5] if len(parts) > 5 else '')[:120],
                })
except Exception:
    pass
postex['interesting_mounts'] = _interesting[:30]

_cred_files = []
for _p in (
    '~/.docker/config.json', '/root/.docker/config.json',
    '/etc/docker/daemon.json',
    '/etc/containerd/config.toml',
    '~/.kube/config', '/root/.kube/config',
    '/etc/kubernetes/admin.conf', '/etc/kubernetes/kubelet.conf',
    '~/.config/containers/auth.json',
    '/var/run/secrets/kubernetes.io/serviceaccount/token',
    '/run/secrets/kubernetes.io/serviceaccount/token',
    '/var/lib/kubelet/config.yaml',
    '/var/lib/kubelet/kubeconfig',
):
    _p2 = os.path.expanduser(_p)
    if os.path.exists(_p2):
        try:
            _st = os.stat(_p2)
            _cred_files.append({
                'path': _p2,
                'readable': os.access(_p2, os.R_OK),
                'mode': oct(_st.st_mode)[-4:],
                'size': _st.st_size,
                'is_dir': os.path.isdir(_p2),
            })
        except Exception:
            pass
postex['credential_files'] = _cred_files
for _c in _cred_files:
    if _c.get('readable') and 'serviceaccount/token' in (_c.get('path') or ''):
        postex['container_breakout_indicators'].append(
            f'readable SA token: {_c.get("path")}'
        )
        break

_rp = {}
if 'docker' in result['runtimes']:
    _rp['docker'] = {
        'in_docker_group': any((g.get('name') or '').lower() == 'docker'
                               for g in postex['groups']['all']),
        'socket_writable': any(s.get('path','').endswith('docker.sock') and s.get('writable')
                               for s in postex['socket_access']),
        'client_ok': bool(sh('docker info >/dev/null 2>&1 && echo yes').strip()),
        'privesc_note': 'writable docker.sock OR docker group -> mount host / into a container = root',
    }
if 'podman' in result['runtimes']:
    _rp['podman'] = {
        'in_podman_group': any((g.get('name') or '').lower() == 'podman'
                               for g in postex['groups']['all']),
        'rootless_probe': sh('podman info --format "{{.Host.Security.Rootless}}" 2>/dev/null').strip(),
    }
if 'lxd' in result['runtimes'] or 'lxc' in result['runtimes']:
    _rp['lxd'] = {
        'in_lxd_group': any((g.get('name') or '').lower() in ('lxd','lxc')
                            for g in postex['groups']['all']),
        'socket_present': any('lxd' in (s.get('path') or '') for s in postex['socket_access']),
        'lxc_ok': bool(sh('lxc list >/dev/null 2>&1 && echo yes').strip()),
        'privesc_note': (
            'lxd group -> lxc init img c -c security.privileged=true; '
            'lxc config device add c host disk source=/ path=/mnt/host -> root'
        ),
    }
if result.get('kubernetes') or 'kubernetes' in result['detected_runtimes']:
    _rp['kubernetes'] = {
        'sa_token_readable': any(
            'serviceaccount/token' in (c.get('path') or '') and c.get('readable')
            for c in _cred_files
        ),
        'kubeconfig_readable': any(
            (c.get('path') or '').endswith('config') and c.get('readable')
            for c in _cred_files
        ),
    }
result['postex_runtime'] = _rp
result['postex'] = postex

running = sum(1 for c in result['containers']
              if str(c.get('state', c.get('status', ''))).lower() in ('running', 'up'))

result['summary'] = {
    'runtimes': ', '.join(result['detected_runtimes']) if result['detected_runtimes'] else 'none detected',
    'containers_total': len(result['containers']),
    'containers_running': running,
    'images': len(result['images']),
    'networks': len(result['networks']),
    'volumes': len(result['volumes']),
    'pods': len(result['pods']),
    'compose_projects': len(result['compose_projects']),
    'kubernetes': 'yes' if result['kubernetes'] else 'N/A',
    'runtime_sockets': len(result['runtime_sockets']),
    'systemd_units': len(result['systemd_units']),
    'postex_high_value_groups': len(postex['groups']['high_value_membership']),
    'postex_writable_sockets': sum(1 for s in postex['socket_access'] if s.get('writable')),
    'postex_inside_container': 'yes' if any(_ic.values()) else 'no',
    'postex_breakout_indicators': len(postex['container_breakout_indicators']),
}
_emit(result)
'''

def _collector_source_cve():
    return r'''
import json, os, re, subprocess

def sh(cmd, timeout=8):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

def which(name):
    return bool(sh(f'command -v {name} 2>/dev/null').strip())

def first_version(s):
    m = re.search(r'(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?', s or '')
    return m.group(0) if m else ''

def pack(installed, raw):
    raw = (raw or '').strip()
    return {
        'installed': bool(installed),
        'raw': raw,
        'version': first_version(raw) if installed and raw else ('N/A' if not installed else ''),
    }

runc_raw = ''
runc_installed = which('runc')
if runc_installed:
    runc_raw = sh('runc --version 2>/dev/null').strip()
else:
    for alt in (
        '/usr/libexec/docker/runc', '/usr/lib/docker/runc',
        '/usr/libexec/containerd/runc', '/opt/containerd/bin/runc',
        '/usr/sbin/runc', '/usr/bin/runc', '/usr/local/sbin/runc',
    ):
        if os.path.exists(alt):
            runc_installed = True
            runc_raw = sh(f'{alt} --version 2>/dev/null').strip()
            break
runc_info = pack(runc_installed, runc_raw)

crun_installed = which('crun')
crun_info = pack(crun_installed, sh('crun --version 2>/dev/null') if crun_installed else '')

containerd_installed = which('containerd')
containerd_info = pack(containerd_installed, sh('containerd --version 2>/dev/null') if containerd_installed else '')

docker_installed = which('docker')
docker_raw = ''
if docker_installed:
    docker_raw = sh('docker version --format "{{.Server.Version}}" 2>/dev/null').strip()
    if not docker_raw:
        docker_raw = sh('docker --version 2>/dev/null').strip()
docker_info = pack(docker_installed, docker_raw)

podman_installed = which('podman')
podman_info = pack(podman_installed, sh('podman --version 2>/dev/null') if podman_installed else '')

crio_installed = bool(which('crio')
    or os.path.exists('/var/run/crio/crio.sock')
    or os.path.exists('/run/crio/crio.sock'))
crio_raw = ''
if crio_installed:
    crio_raw = sh('crio --version 2>/dev/null').strip()
    if not crio_raw:
        crio_raw = sh('crio version 2>/dev/null').strip()
crio_info = pack(crio_installed, crio_raw)

k8s_installed = bool(which('kubectl') or which('kubelet'))
k8s_raw = ''
if which('kubectl'):
    k8s_raw = sh('kubectl version --client 2>/dev/null').strip()
if not k8s_raw and which('kubelet'):
    k8s_raw = sh('kubelet --version 2>/dev/null').strip()
k8s_info = pack(k8s_installed, k8s_raw)

lxc_installed = bool(which('lxc') or which('lxc-ls'))
lxc_raw = sh('lxc --version 2>/dev/null').strip() if which('lxc') else ''
lxc_info = pack(lxc_installed, lxc_raw)

lxd_installed = bool(
    which('lxd') or which('lxc')
    or os.path.isdir('/var/snap/lxd')
    or os.path.isdir('/snap/lxd')
)
lxd_info = pack(lxd_installed, lxc_raw)

nerdctl_installed = which('nerdctl')
nerdctl_info = pack(nerdctl_installed, sh('nerdctl --version 2>/dev/null') if nerdctl_installed else '')

result = {
    'mode': 'cve',
    'runtimes': {
        'runc': runc_info,
        'crun': crun_info,
        'containerd': containerd_info,
        'docker': docker_info,
        'podman': podman_info,
        'crio': crio_info,
        'kubernetes': k8s_info,
        'lxc': lxc_info,
        'lxd': lxd_info,
        'nerdctl': nerdctl_info,
    },
}
_emit(result)
'''

def build_command(mode='enumerate'):
    if mode == 'cve':
        return build_linux_collector_command(_collector_source_cve())
    return build_linux_collector_command(_collector_source())

def _arg_values(args):
    if args is None:
        return set()
    if isinstance(args, dict):
        s = set()
        for k, v in args.items():
            if v is True or v is None or v == '':
                s.add(str(k))
            else:
                s.add(str(k))
                s.add(str(v))
        return s
    if isinstance(args, (list, tuple, set)):
        return {str(x) for x in args}
    try:
        ns = vars(args)
    except TypeError:
        return {str(args)}
    s = set()
    for k, v in ns.items():
        if v:
            s.add(k)
            s.add(str(v))
    return s


def _has_cve_flag(args):
    a = _arg_values(args)
    return '--cve' in a or 'cve' in a


def _has_help_flag(args):
    a = _arg_values(args)
    return ('-h' in a) or ('--help' in a) or ('help' in a)

_HELP_TEXT = """\
containers — Linux container runtime enumeration + CVE check

USAGE
    containers [OPTIONS]

OPTIONS
    -h, --help    Show this help. Nothing runs on the target.
    --cve         Version-only scan; CVEs matched locally on the operator side.

MODES
    (default)     Enumerate runtimes + workloads and report post-exploitation
                  primitives: user/groups, high-value group membership
                  (docker, lxd, disk, ...), runtime socket access, mounts,
                  credential files, capabilities, per-runtime privesc notes.

    --cve         Probe only runtime versions (runc, crun, containerd, docker,
                  podman, crio, kubernetes, lxc, lxd, nerdctl) and match them
                  against the local RUNTIME_CVES database. Missing runtimes
                  are reported as N/A.

EXAMPLES
    containers              Full enumeration + postex report.
    containers --cve        CVE-only scan.
    containers -h           This help.
"""

_SEV_LABEL = {
    'critical': 'CRITICAL',
    'high':     'HIGH',
    'medium':   'MEDIUM',
    'low':      'LOW',
    'info':     'INFO',
}

_W = 72


def _hdr(title):
    return [
        '',
        '=' * _W,
        f'  {title}',
        '=' * _W,
    ]


def _sec(title):
    return [
        '',
        f'  {title}',
        '  ' + '-' * len(title),
    ]


def _row(label, value, lw=16):
    return f'    {label:<{lw}} {value}'

def format_cve_report(enriched):
    analysis = (enriched or {}).get('analysis') or {}
    runtimes = analysis.get('runtimes') or {}
    findings = analysis.get('findings') or []

    sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in findings:
        sev = (f.get('severity') or '').lower()
        if sev in sev_counts:
            sev_counts[sev] += 1

    total = analysis.get('total', len(findings))

    out = []
    out += _hdr('Container Runtime — CVE Analysis')

    out += _sec('Summary')
    out.append(_row('Total findings', str(total)))
    out.append(_row('Critical',       str(sev_counts['critical'])))
    out.append(_row('High',           str(sev_counts['high'])))
    out.append(_row('Medium',         str(sev_counts['medium'])))
    out.append(_row('Low / Info',     str(sev_counts['low'] + sev_counts['info'])))

    out += _sec('Detected Runtime Versions')
    names = sorted(runtimes.keys())
    if names:
        nw = max(len(n) for n in names) + 2
        vw = 22
        out.append(f"    {'RUNTIME':<{nw}}{'VERSION':<{vw}}STATUS")
        out.append(f"    {'-' * (nw - 2):<{nw}}{'-' * (vw - 2):<{vw}}{'-' * 20}")
        for name in names:
            info = runtimes.get(name) or {}
            ver = info.get('version') or 'N/A'
            cnt = info.get('count', 0)
            if ver == 'N/A' or not info.get('installed', True):
                status = 'not installed'
            elif cnt == 0:
                status = 'up to date'
            else:
                status = f'{cnt} CVE' + ('s' if cnt != 1 else '')
            out.append(f"    {name:<{nw}}{ver:<{vw}}{status}")
    else:
        out.append('    (no runtimes matched)')

    out += _sec('Findings')
    if not findings:
        out.append('    No known CVEs match the detected runtime versions.')
        return '\n'.join(out)

    grouped = {}
    for f in findings:
        grouped.setdefault((f.get('severity') or 'info').lower(), []).append(f)

    idx = 0
    for sev in ('critical', 'high', 'medium', 'low', 'info'):
        bucket = grouped.get(sev)
        if not bucket:
            continue
        out.append('')
        out.append(f"  ── {_SEV_LABEL.get(sev, sev.upper())} ({len(bucket)}) " + '─' * 30)
        for f in bucket:
            idx += 1
            out.append('')
            out.append(f"  [{idx}] {f.get('cve')}  —  {_SEV_LABEL.get(sev, sev.upper())}")
            out.append(f"      Runtime  : {f.get('runtime')} {f.get('version')}")
            out.append(f"      Fixed in : {f.get('fixed_in') or 'n/a'}")
            out.append(f"      Title    : {f.get('title')}")
            if f.get('description'):
                out.append(f"      Details  : {f.get('description')}")
            out.append(f"      Vector   : {f.get('vector') or 'n/a'}"
                       f"     Exploit: {f.get('exploit') or 'n/a'}")

    return '\n'.join(out)

def _format_postex_section(result):
    postex = (result or {}).get('postex') or {}
    if not postex:
        return ''

    out = []
    out += _hdr('Post-Exploitation Indicators')

    quick = []
    for g in (postex.get('groups') or {}).get('high_value_membership') or []:
        quick.append(f"member of '{g.get('group')}'  ->  {g.get('reason')}")
    for s in postex.get('socket_access') or []:
        if s.get('writable'):
            quick.append(f"writable runtime socket: {s.get('path')}")
    for c in postex.get('credential_files') or []:
        if c.get('readable') and 'serviceaccount/token' in (c.get('path') or ''):
            quick.append(f"readable SA token: {c.get('path')}")
    if (postex.get('privileges') or {}).get('cap_level') == 'likely_privileged':
        quick.append('process has privileged capabilities (CapEff looks full)')

    if quick:
        out += _sec('Quick Wins')
        for q in quick:
            out.append(f"    [!] {q}")

    cur = postex.get('current_user') or {}
    if cur:
        out += _sec('Current User')
        line = (
            f"{cur.get('username','?')}  "
            f"(uid={cur.get('uid')} gid={cur.get('gid')} "
            f"euid={cur.get('euid')} egid={cur.get('egid')})"
        )
        out.append(_row('Identity', line))
        out.append(_row('Is root', 'yes' if cur.get('is_root') else 'no'))
        if cur.get('home'):
            out.append(_row('Home', cur.get('home')))
        if cur.get('shell'):
            out.append(_row('Shell', cur.get('shell')))

        groups = (postex.get('groups') or {}).get('all') or []
        if groups:
            gstr = ', '.join(
                (g.get('name') or str(g.get('gid'))) for g in groups if isinstance(g, dict)
            )
            out.append(_row('Groups', gstr))

    sa = postex.get('socket_access') or []
    if sa:
        out += _sec('Runtime Socket Access')
        out.append(f"    {'PATH':<46}{'MODE':<8}{'OWNER':<20}{'ACCESS'}")
        out.append(f"    {'-'*44:<46}{'-'*6:<8}{'-'*18:<20}{'-'*6}")
        for s in sa:
            path = s.get('path', '')
            if len(path) > 44:
                path = '…' + path[-43:]
            mode = s.get('mode', '?')
            owner = f"{s.get('owner','?')}:{s.get('group','?')}"
            if len(owner) > 18:
                owner = owner[:17] + '…'
            flags = ('R' if s.get('readable') else '-') + ('W' if s.get('writable') else '-')
            out.append(f"    {path:<46}{mode:<8}{owner:<20}[{flags}]")
        out.append('    (R = readable, W = writable)')

    ic = postex.get('inside_container') or {}
    if any(v for v in ic.values()):
        out += _sec('Inside-Container Indicators')
        if ic.get('dockerenv'):
            out.append(_row('/.dockerenv', 'present'))
        if ic.get('containerenv'):
            out.append(_row('/run/.containerenv', 'present'))
        if ic.get('cgroup_hints'):
            out.append(_row('cgroup hints', ', '.join(ic['cgroup_hints'])))
        if ic.get('mount_hints'):
            out.append(_row('mount hints', ', '.join(ic['mount_hints'])))
        if ic.get('env_hints'):
            out.append(_row('env hints', ', '.join(ic['env_hints'])))

    priv = postex.get('privileges') or {}
    if priv:
        out += _sec('Process Privileges')
        for key, label in (
            ('cap_level', 'Cap level'),
            ('CapEff', 'CapEff'),
            ('CapPrm', 'CapPrm'),
            ('CapBnd', 'CapBnd'),
            ('CapAmb', 'CapAmb'),
            ('Seccomp', 'Seccomp'),
            ('NoNewPrivs', 'NoNewPrivs'),
        ):
            if key in priv:
                out.append(_row(label, priv[key]))

    mounts = postex.get('interesting_mounts') or []
    if mounts:
        out += _sec('Interesting Mounts')
        for m in mounts[:20]:
            mp = m.get('mount_point', '')
            fst = m.get('fstype', '') or ''
            opts = m.get('options', '') or ''
            tail = f"({fst})" if fst else ''
            if opts:
                tail += f"  opts={opts}"
            out.append(f"    {mp}  {tail}")

    creds = postex.get('credential_files') or []
    if creds:
        out += _sec('Credential / Config Files')
        out.append(f"    {'R':<3}{'PATH':<52}{'MODE':<8}{'SIZE':>8}")
        out.append(f"    {'-'*1:<3}{'-'*50:<52}{'-'*6:<8}{'-'*8:>8}")
        for c in creds:
            path = c.get('path', '')
            if len(path) > 50:
                path = '…' + path[-49:]
            out.append(
                f"    {'R' if c.get('readable') else '-':<3}"
                f"{path:<52}{c.get('mode','?'):<8}{c.get('size',0):>8}"
            )
        out.append('    (R = readable by current user)')

    rp = (result or {}).get('postex_runtime') or {}
    if rp:
        out += _sec('Runtime-Specific Notes')
        for rt, info in rp.items():
            out.append(f"    [{rt}]")
            for k, v in info.items():
                if isinstance(v, bool):
                    v = 'yes' if v else 'no'
                out.append(_row(k, v, lw=20))

    bo = postex.get('container_breakout_indicators') or []
    if bo:
        out += _sec('Breakout / Privesc Indicators')
        for b in bo:
            out.append(f"    [!] {b}")

    out.append('')
    return '\n'.join(out)


def format_containers_report_with_postex(result):
    base = format_containers_report(result) or ''
    extra = _format_postex_section(result)
    return base + (('\n' + extra) if extra else '')

@plugin.command(
    name='containers',
    platforms=['linux', 'unix'],
    description=(
        'Enumerate container runtimes and workloads (Docker, Podman, containerd, '
        'CRI-O, LXC/LXD, Kubernetes) plus post-exploitation context. '
        'Use --cve to run a version-only scan and match against known runtime CVEs '
        '(CVE matching is done on the plugin side). '
        'Use -h/--help for detailed usage.'
    ),
)
def run(session: SessionContext, args):
    if _has_help_flag(args):
        return _HELP_TEXT

    if _has_cve_flag(args):
        def cve_formatter(result):
            analysis = _analyze_runtime_versions(result or {})
            return format_cve_report({'raw': result, 'analysis': analysis})

        return run_collector_plugin(
            session,
            'containers_cve',
            lambda: build_command('cve'),
            None,
            cve_formatter,
            timeout=45.0,
        )

    return run_collector_plugin(
        session,
        'containers',
        build_command,
        None,
        format_containers_report_with_postex,
        timeout=90.0,
    )