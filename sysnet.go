package netool

import (
	"github.com/vishvananda/netlink"
)

func Index2Nic(index int) (netlink.Link,error) {
	link,err := netlink.LinkByIndex(index)
	if err != nil {
		return nil,err
	}
	return link,nil
}

