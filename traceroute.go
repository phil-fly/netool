package netool

import (
	"bytes"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"os"
	"time"
)

//TraceRoute4 ipv4类型的Traceroute探测，输出结果信息以及错误信息
func TraceRoute4(host string) (string,error){
	// Tracing an IP packet route to www.baidu.com.
	var results bytes.Buffer

	ips, err := net.LookupIP(host)
	if err != nil {
		return results.String(),err
	}

	var dst net.IPAddr
	for _, ip := range ips {
		if ip.To4() != nil {
			dst.IP = ip
			//fmt.Printf("using %v for tracing an IP packet route to %s\n", dst.IP, host)
			break
		}
	}

	if dst.IP == nil {
		return results.String(),fmt.Errorf("目的地址格式错误")
	}

	c, err := net.ListenPacket("ip4:icmp", "0.0.0.0") // ICMP for IPv4
	if err != nil {
		return results.String(), err
	}
	defer c.Close()
	p := ipv4.NewPacketConn(c)

	if err := p.SetControlMessage(ipv4.FlagTTL|ipv4.FlagSrc|ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		return "", err
	}
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Data: []byte("netcheck"),
		},
	}

	rb := make([]byte, 1500)
	for i := 1; i <= 64; i++ { // up to 64 hops
		wm.Body.(*icmp.Echo).Seq = i
		wb, err := wm.Marshal(nil)
		if err != nil {
			return "",err
		}
		if err := p.SetTTL(i); err != nil {
			return "",err
		}

		// In the real world usually there are several
		// multiple traffic-engineered paths for each hop.
		// You may need to probe a few times to each hop.
		begin := time.Now()
		if _, err := p.WriteTo(wb, nil, &dst); err != nil {
			return "",err
		}
		if err := p.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			return "",err
		}
		n, cm, peer, err := p.ReadFrom(rb)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
				continue
			}
			log.Fatal(err)
		}
		rm, err := icmp.ParseMessage(1, rb[:n])
		if err != nil {
			return "",err
		}
		rtt := time.Since(begin)
		link,err := Index2Nic(cm.IfIndex)


		// In the real world you need to determine whether the
		// received message is yours using ControlMessage.Src,
		// ControlMessage.Dst, icmp.Echo.ID and icmp.Echo.Seq.
		switch rm.Type {
		case ipv4.ICMPTypeTimeExceeded:
			//src := cm.Src.String()
			names, _ := net.LookupAddr(peer.String())
			if link != nil {
				results.WriteString(fmt.Sprintf("	[-] 网卡: %s Src: %s Dst: %s%+v 耗时: %v.", link.Attrs().Name,cm.Dst.String(),cm.Src.String(),names,rtt.String()))

			}else{
				results.WriteString(fmt.Sprintf("	[-] Src: %s Dst: %s%+v 耗时: %v.", cm.Dst.String(),cm.Src.String(),names,rtt.String()))
			}

		case ipv4.ICMPTypeEchoReply:
			names, _ := net.LookupAddr(peer.String())
			if link != nil {
				results.WriteString(fmt.Sprintf("	[+] 网卡: %s Src: %s Dst: %s%+v 耗时: %v.", link.Attrs().Name,cm.Dst.String(),cm.Src.String(),names,rtt.String()))
			}else{
				results.WriteString(fmt.Sprintf("	[+] Src: %s Dst: %s%+v 耗时: %v.", cm.Dst.String(),cm.Src.String(),names,rtt.String()))
			}

			return results.String(),nil
		case ipv4.ICMPTypeDestinationUnreachable:
			if cm.Src.String() == "127.0.0.1" {
				continue
			}

			if link != nil{
				results.WriteString(fmt.Sprintf("	[-] 网卡: %s Src: %s Dst: %s 耗时: %v 无法访问目标主机.",link.Attrs().Name,cm.Dst.String(),cm.Src.String(),rtt.String()))
			}else{
				results.WriteString(fmt.Sprintf("	[-] Src: %s Dst: %s 耗时: %v 无法访问目标主机.",cm.Dst.String(),cm.Src.String(),rtt.String()))
			}

			return results.String(),nil
		default:
			//src = cm.Src.String()
			//log.Errorf("	[-] 未知的icmp消息类型: %+v", rm)
		}
	}


	return results.String(),nil
}

