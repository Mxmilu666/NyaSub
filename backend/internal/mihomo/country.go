package mihomo

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// countryAliases maps country codes seen in node names to an ISO alpha-2 code
// used for the flag emoji. UK is an alias for GB; EU/XK are common extras.
var countryAliases = map[string]string{
	"AD":          "AD",
	"AE":          "AE",
	"AF":          "AF",
	"AG":          "AG",
	"AI":          "AI",
	"AL":          "AL",
	"AM":          "AM",
	"AO":          "AO",
	"AR":          "AR",
	"AT":          "AT",
	"AU":          "AU",
	"AW":          "AW",
	"AZ":          "AZ",
	"BA":          "BA",
	"BB":          "BB",
	"BD":          "BD",
	"BE":          "BE",
	"BF":          "BF",
	"BG":          "BG",
	"BH":          "BH",
	"BI":          "BI",
	"BJ":          "BJ",
	"BL":          "BL",
	"BM":          "BM",
	"BN":          "BN",
	"BO":          "BO",
	"BQ":          "BQ",
	"BR":          "BR",
	"BS":          "BS",
	"BV":          "BV",
	"BW":          "BW",
	"BY":          "BY",
	"BZ":          "BZ",
	"CA":          "CA",
	"CC":          "CC",
	"CD":          "CD",
	"CF":          "CF",
	"CG":          "CG",
	"CH":          "CH",
	"CI":          "CI",
	"CK":          "CK",
	"CL":          "CL",
	"CM":          "CM",
	"CN":          "CN",
	"CO":          "CO",
	"CR":          "CR",
	"CU":          "CU",
	"CV":          "CV",
	"CW":          "CW",
	"CX":          "CX",
	"CY":          "CY",
	"CZ":          "CZ",
	"DE":          "DE",
	"DJ":          "DJ",
	"DK":          "DK",
	"DM":          "DM",
	"DO":          "DO",
	"DZ":          "DZ",
	"EC":          "EC",
	"EE":          "EE",
	"EG":          "EG",
	"EH":          "EH",
	"ER":          "ER",
	"ES":          "ES",
	"ET":          "ET",
	"FI":          "FI",
	"FJ":          "FJ",
	"FK":          "FK",
	"FM":          "FM",
	"FO":          "FO",
	"FR":          "FR",
	"GA":          "GA",
	"GB":          "GB",
	"GD":          "GD",
	"GE":          "GE",
	"GF":          "GF",
	"GG":          "GG",
	"GH":          "GH",
	"GI":          "GI",
	"GL":          "GL",
	"GM":          "GM",
	"GN":          "GN",
	"GP":          "GP",
	"GQ":          "GQ",
	"GR":          "GR",
	"GS":          "GS",
	"GT":          "GT",
	"GU":          "GU",
	"GW":          "GW",
	"GY":          "GY",
	"HK":          "HK",
	"HM":          "HM",
	"HN":          "HN",
	"HR":          "HR",
	"HT":          "HT",
	"HU":          "HU",
	"ID":          "ID",
	"IE":          "IE",
	"IL":          "IL",
	"IM":          "IM",
	"IN":          "IN",
	"IO":          "IO",
	"IQ":          "IQ",
	"IR":          "IR",
	"IS":          "IS",
	"IT":          "IT",
	"JE":          "JE",
	"JM":          "JM",
	"JO":          "JO",
	"JP":          "JP",
	"KE":          "KE",
	"KG":          "KG",
	"KH":          "KH",
	"KI":          "KI",
	"KM":          "KM",
	"KN":          "KN",
	"KP":          "KP",
	"KR":          "KR",
	"KW":          "KW",
	"KY":          "KY",
	"KZ":          "KZ",
	"LA":          "LA",
	"LB":          "LB",
	"LC":          "LC",
	"LI":          "LI",
	"LK":          "LK",
	"LR":          "LR",
	"LS":          "LS",
	"LT":          "LT",
	"LU":          "LU",
	"LV":          "LV",
	"LY":          "LY",
	"MA":          "MA",
	"MC":          "MC",
	"MD":          "MD",
	"ME":          "ME",
	"MF":          "MF",
	"MG":          "MG",
	"MH":          "MH",
	"MK":          "MK",
	"ML":          "ML",
	"MM":          "MM",
	"MN":          "MN",
	"MO":          "MO",
	"MP":          "MP",
	"MQ":          "MQ",
	"MR":          "MR",
	"MS":          "MS",
	"MT":          "MT",
	"MU":          "MU",
	"MV":          "MV",
	"MW":          "MW",
	"MX":          "MX",
	"MY":          "MY",
	"MZ":          "MZ",
	"NA":          "NA",
	"NC":          "NC",
	"NE":          "NE",
	"NF":          "NF",
	"NG":          "NG",
	"NI":          "NI",
	"NL":          "NL",
	"NO":          "NO",
	"NP":          "NP",
	"NR":          "NR",
	"NU":          "NU",
	"NZ":          "NZ",
	"OM":          "OM",
	"PA":          "PA",
	"PE":          "PE",
	"PF":          "PF",
	"PG":          "PG",
	"PH":          "PH",
	"PK":          "PK",
	"PL":          "PL",
	"PM":          "PM",
	"PN":          "PN",
	"PR":          "PR",
	"PS":          "PS",
	"PT":          "PT",
	"PW":          "PW",
	"PY":          "PY",
	"QA":          "QA",
	"RE":          "RE",
	"RO":          "RO",
	"RS":          "RS",
	"RU":          "RU",
	"RW":          "RW",
	"SA":          "SA",
	"SB":          "SB",
	"SC":          "SC",
	"SD":          "SD",
	"SE":          "SE",
	"SG":          "SG",
	"SH":          "SH",
	"SI":          "SI",
	"SJ":          "SJ",
	"SK":          "SK",
	"SL":          "SL",
	"SM":          "SM",
	"SN":          "SN",
	"SO":          "SO",
	"SR":          "SR",
	"ST":          "ST",
	"SV":          "SV",
	"SX":          "SX",
	"SY":          "SY",
	"SZ":          "SZ",
	"TC":          "TC",
	"TD":          "TD",
	"TG":          "TG",
	"TH":          "TH",
	"TJ":          "TJ",
	"TK":          "TK",
	"TL":          "TL",
	"TM":          "TM",
	"TN":          "TN",
	"TO":          "TO",
	"TR":          "TR",
	"TT":          "TT",
	"TV":          "TV",
	"TW":          "TW",
	"TZ":          "TZ",
	"UA":          "UA",
	"UG":          "UG",
	"UM":          "UM",
	"US":          "US",
	"UY":          "UY",
	"UZ":          "UZ",
	"VA":          "VA",
	"VC":          "VC",
	"VE":          "VE",
	"VG":          "VG",
	"VI":          "VI",
	"VN":          "VN",
	"VU":          "VU",
	"WF":          "WF",
	"WS":          "WS",
	"YE":          "YE",
	"YT":          "YT",
	"ZA":          "ZA",
	"ZM":          "ZM",
	"ZW":          "ZW",
	"UK":          "GB",
	"EU":          "EU",
	"XK":          "XK",
	"台湾":          "TW",
	"臺灣":          "TW",
	"台北":          "TW",
	"TAIWAN":      "TW",
	"TAIPEI":      "TW",
	"香港":          "HK",
	"HONGKONG":    "HK",
	"日本":          "JP",
	"JAPAN":       "JP",
	"美国":          "US",
	"美國":          "US",
	"USA":         "US",
	"英国":          "GB",
	"英國":          "GB",
	"ENGLAND":     "GB",
	"新加坡":         "SG",
	"SINGAPORE":   "SG",
	"韩国":          "KR",
	"韓國":          "KR",
	"KOREA":       "KR",
	"德国":          "DE",
	"德國":          "DE",
	"GERMANY":     "DE",
	"法国":          "FR",
	"法國":          "FR",
	"FRANCE":      "FR",
	"荷兰":          "NL",
	"荷蘭":          "NL",
	"NETHERLANDS": "NL",
	"俄罗斯":         "RU",
	"俄羅斯":         "RU",
	"RUSSIA":      "RU",
	"加拿大":         "CA",
	"CANADA":      "CA",
	"澳大利亚":        "AU",
	"澳洲":          "AU",
	"AUSTRALIA":   "AU",
	"印度":          "IN",
	"INDIA":       "IN",
	"土耳其":         "TR",
	"TURKEY":      "TR",
	"阿联酋":         "AE",
	"巴西":          "BR",
	"BRAZIL":      "BR",
}

// CountryFlag returns a flag emoji for the last country code token in name.
// Names that already start with a regional-indicator flag are left untouched.
func CountryFlag(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	for _, r := range name {
		if r >= 0x1F1E6 && r <= 0x1F1FF {
			return ""
		}
	}
	code := ""
	for _, token := range strings.FieldsFunc(name, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if iso, ok := countryAliases[strings.ToUpper(token)]; ok {
			code = iso
		}
	}
	return flagFromISO(code)
}

// NormalizeCountry validates and normalizes a manual country override. Empty
// and "auto" both mean automatic detection from the node name.
func NormalizeCountry(value string) (string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" || value == "AUTO" {
		return "", nil
	}
	if iso, ok := countryAliases[value]; ok {
		return iso, nil
	}
	return "", fmt.Errorf("invalid country code")
}

func flagFromISO(code string) string {
	code = strings.ToUpper(code)
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return ""
	}
	return string([]rune{
		rune(0x1F1E6 + rune(code[0]) - 'A'),
		rune(0x1F1E6 + rune(code[1]) - 'A'),
	})
}

func nodeFlag(name, country string) string {
	if country != "" {
		if flag := flagFromISO(country); flag != "" {
			return flag
		}
	}
	if flag := CountryFlag(name); flag != "" {
		return flag
	}
	trimmed := strings.TrimSpace(name)
	runes := []rune(trimmed)
	if len(runes) >= 2 && runes[0] >= 0x1F1E6 && runes[0] <= 0x1F1FF && runes[1] >= 0x1F1E6 && runes[1] <= 0x1F1FF {
		return string(runes[:2])
	}
	return ""
}

func stripLeadingFlags(name string) string {
	name = strings.TrimSpace(name)
	for {
		r, size := utf8.DecodeRuneInString(name)
		if r < 0x1F1E6 || r > 0x1F1FF {
			return name
		}
		name = strings.TrimSpace(name[size:])
	}
}

// exportDisplayName applies a manual country override, or detects one from the
// node name when no override is set.
func exportDisplayName(name, country string) string {
	name = cleanExportName(name)
	if country != "" {
		if flag := flagFromISO(country); flag != "" {
			return flag + " " + stripLeadingFlags(name)
		}
	}
	if flag := CountryFlag(name); flag != "" {
		return flag + " " + name
	}
	return name
}
