package types

// GeoIPInfo represents comprehensive GeoIP information
type GeoIPInfo struct {
	IP          string  `json:"ip" xml:"ip" csv:"ip"`
	Country     string  `json:"country" xml:"country" csv:"country"`
	CountryCode string  `json:"country_code" xml:"country_code" csv:"country_code"`
	Region      string  `json:"region" xml:"region" csv:"region"`
	RegionCode  string  `json:"region_code" xml:"region_code" csv:"region_code"`
	City        string  `json:"city" xml:"city" csv:"city"`
	Latitude    float64 `json:"latitude" xml:"latitude" csv:"latitude"`
	Longitude   float64 `json:"longitude" xml:"longitude" csv:"longitude"`
	PostalCode  string  `json:"postal_code" xml:"postal_code" csv:"postal_code"`
	TimeZone    string  `json:"timezone" xml:"timezone" csv:"timezone"`
	ASN         uint    `json:"asn" xml:"asn" csv:"asn"`
	ASNOrg      string  `json:"asn_org" xml:"asn_org" csv:"asn_org"`
	ISP         string  `json:"isp" xml:"isp" csv:"isp"`
}
