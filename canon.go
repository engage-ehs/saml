package saml

import (
	"fmt"
	"io"
	"sort"

	"github.com/beevik/etree"
)

func canonicalize(elt *etree.Element, dst io.Writer, nss *pt) {

	// first loop: detect prefix not yet known
	var spaces []etree.Attr
	if !nss.Seen(elt.Space) {
		spaces = append(spaces, etree.Attr{Space: "xmlns", Key: elt.Space, Value: elt.NamespaceURI()})
		nss.Rec(elt.Space)
	}
	for _, at := range elt.Attr {
		if at.Space != "" && at.Space != "xmlns" && !nss.Seen(at.Space) {
			spaces = append(spaces, etree.Attr{Space: "xmlns", Key: at.Space, Value: at.NamespaceURI()})
			nss.Rec(at.Space)
		}
	}
	sort.Slice(spaces, func(i, j int) bool { return spaces[i].Key < spaces[j].Key })

	fmt.Fprintf(dst, "<%s", elt.FullTag())
	for _, sp := range spaces {
		if sp.Key == "" {
			// default namespace
			fmt.Fprintf(dst, " xmlns=\"%s\"", sp.Value)
		} else {
			fmt.Fprintf(dst, " xmlns:%s=\"%s\"", sp.Key, sp.Value)
		}
	}

	sort.Slice(elt.Attr, func(i, j int) bool { return elt.Attr[i].Key < elt.Attr[j].Key })

	for _, at := range elt.Attr {
		if at.Space == "xmlns" || at.Key == "xmlns" {
			// namespaces handled before attributes
			continue
		}

		fmt.Fprintf(dst, " %s=\"%s\"", at.FullKey(), at.Value)
	}
	fmt.Fprintf(dst, ">")
	for _, c := range elt.Child {
		switch c := c.(type) {
		case *etree.Element:
			canonicalize(c, dst, &pt{next: nss.next})
		case *etree.CharData:
			io.WriteString(dst, c.Data)
		case *etree.Comment:
			// TODO(exclude comments, …)
		case *etree.Directive:
		case *etree.ProcInst:
		}
	}

	fmt.Fprintf(dst, "</%s>", elt.FullTag())
}

// dict is a lightweight key-value storage for XML namespaces and prefix. It uses a linked list for
// trivial sharing: this is useful as namspaces prefix are scoped in XML
// https://www.w3.org/TR/2006/REC-xml-names11-20060816/ § 6.1
type dict struct {
	next *dict

	Prefix string
}

// pointer allow for structural sharing
type pt struct{ next *dict }

func (s pt) Seen(prefix string) bool {
	for p := s.next; p != nil; p = p.next {
		if p.Prefix == prefix {
			return true
		}
	}
	return false
}

func (s *pt) Rec(prefix string) { s.next = &dict{next: s.next, Prefix: prefix} }
