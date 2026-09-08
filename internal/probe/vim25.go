// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/xml"
	"fmt"
)

// vim25RetrieveServiceContentRequest is the SOAP envelope for
// ServiceInstance.RetrieveServiceContent — the vSphere API's own
// discovery call, confirmed live to need no credentials against a real
// ESXi host, the same as govmomi (the Go vSphere SDK) sends it.
const vim25RetrieveServiceContentRequest = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vim25="urn:vim25">
  <soapenv:Body>
    <vim25:RetrieveServiceContent>
      <vim25:_this type="ServiceInstance">ServiceInstance</vim25:_this>
    </vim25:RetrieveServiceContent>
  </soapenv:Body>
</soapenv:Envelope>`

// vim25AboutInfo is ServiceContent.about — shared by vcenterProbe and
// esxiProbe, the two products that speak this SOAP API and answer this
// exact call identically apart from apiType. Verified against a live
// ESXi host's real reply (see testdata/esxi_8.0.3.xml); vCenter's own
// reply has the identical shape with apiType=VirtualCenter instead.
type vim25AboutInfo struct {
	Name     string `xml:"name"`
	FullName string `xml:"fullName"`
	Version  string `xml:"version"`
	Build    string `xml:"build"`
	APIType  string `xml:"apiType"` // "HostAgent" for ESXi, "VirtualCenter" for vCenter
}

type vim25Envelope struct {
	Body struct {
		RetrieveServiceContentResponse struct {
			Returnval struct {
				About vim25AboutInfo `xml:"about"`
			} `xml:"returnval"`
		} `xml:"RetrieveServiceContentResponse"`
	} `xml:"Body"`
}

// vim25RetrieveAbout runs RetrieveServiceContent against /sdk and returns
// ServiceContent.about. Product identity (apiType) is the caller's job —
// D9 requires vcenterProbe and esxiProbe each reject the other's real
// reply, not just parse whatever version comes back.
func vim25RetrieveAbout(ctx context.Context, t Target) (vim25AboutInfo, error) {
	resp, err := FetchHTTP(ctx, t, Request{
		Path:    "/sdk",
		Method:  "POST",
		Accept:  "text/xml",
		Body:    []byte(vim25RetrieveServiceContentRequest),
		Headers: map[string]string{"Content-Type": "text/xml; charset=utf-8", "SOAPAction": "urn:vim25/8.0"},
	})
	if err != nil {
		return vim25AboutInfo{}, err
	}
	defer resp.Body.Close()

	body, err := ReadBody(resp)
	if err != nil {
		return vim25AboutInfo{}, err
	}

	var env vim25Envelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return vim25AboutInfo{}, fmt.Errorf("%w: RetrieveServiceContent reply is not valid XML: %w", ErrUnparseable, err)
	}
	about := env.Body.RetrieveServiceContentResponse.Returnval.About
	if about.Version == "" {
		return vim25AboutInfo{}, fmt.Errorf("%w: RetrieveServiceContent reply carries no about.version", ErrUnparseable)
	}
	return about, nil
}
