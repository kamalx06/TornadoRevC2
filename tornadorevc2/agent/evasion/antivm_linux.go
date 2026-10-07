//go:build linux

package evasion

import (
	"os"
	"strings"
)

// InVM returns true if the environment looks like a VM or hypervisor.
//
// Checks:
//   1. DMI product_name / sys_vendor / board_vendor
//   2. /proc/cpuinfo `hypervisor` flag
//
// Fails open: if DMI files are unreadable (common in containers), the
// check returns false rather than guessing.
//
// False-positive warning: the DMI marker list contains "microsoft
// corporation", which catches Hyper-V guests (correct) but also
// bare-metal Microsoft Surface hardware and some Azure bare-metal
// SKUs (incorrect). On an engagement where Surface hardware is a
// realistic target, either drop that marker from the list below or
// switch the check to something less ambiguous — the
// `hypervisor` flag in /proc/cpuinfo is the stronger signal, since
// it is set by the kernel only when CPUID reports the hypervisor
// bit and hardware does not set it.
func InVM() bool {
	return dmiMentionsVM() || cpuinfoHypervisorFlag()
}

func dmiMentionsVM() bool {
	files := []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/board_vendor",
	}
	// Lowercase substring matches against the DMI strings. Two of
	// these are ambiguous:
	//
	//   "microsoft corporation"  — matches Hyper-V guests (correct)
	//                              and bare-metal Surface hardware
	//                              and Azure bare-metal SKUs (wrong).
	//   "xen"                    — matches Xen guests (correct) and
	//                              also Amazon EC2 (whose DMI vendor
	//                              is "Xen" on older instance types)
	//                              and Oracle Cloud (which runs KVM
	//                              but reports Xen-compatible DMI on
	//                              some shapes). Both are VMs, so the
	//                              match is not incorrect — just not
	//                              attributable to the hypervisor the
	//                              name suggests.
	//
	// The remaining markers are unambiguous in practice.
	markers := []string{
		"vmware", "virtualbox", "vbox", "qemu", "kvm",
		"xen", "bochs", "parallels", "amazon ec2",
		"google compute", "microsoft corporation",
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		lower := strings.ToLower(string(data))
		for _, m := range markers {
			if strings.Contains(lower, m) {
				return true
			}
		}
	}
	return false
}

func cpuinfoHypervisorFlag() bool {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), " hypervisor")
}