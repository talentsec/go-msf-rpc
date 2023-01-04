package rpc

// Modules

type ModuleExploitsReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type ModuleExploitsRes struct {
	Modules []string `msgpack:"modules"`
}

type ModuleAuxiliaryReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type ModuleAuxiliaryRes struct {
	Modules []string `msgpack:"modules"`
}

type ModulePostReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type ModulePostRes struct {
	Modules []string `msgpack:"modules"`
}

type ModulePayloadsReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type ModulePayloadsRes struct {
	Modules []string `msgpack:"modules"`
}

type ModuleEncodersReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type ModuleEncodersRes struct {
	Modules []string `msgpack:"modules"`
}

type ModuleNopsReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type ModuleNopsRes struct {
	Modules []string `msgpack:"modules"`
}

type ModuleInfoReq struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	ModuleType string
	ModuleName string
}

type ModuleInfoRes struct {
	Name            string          `msgpack:"name"`
	Description     string          `msgpack:"description"`
	License         string          `msgpack:"license"`
	FilePath        string          `msgpack:"filepath"`
	Version         string          `msgpack:"version"`
	Rank            string          `msgpack:"rank"`
	References      [][]interface{} `msgpack:"references"`
	Authors         []string        `msgpack:"authors"`
	Arch            []string        `msgpack:"arch"`
	Platform        []string        `msgpack:"platform"`
	Privileged      bool            `msgpack:"privileged"`
	DisclosureDate  string          `msgpack:"disclosure_date"`
	Finger          Finger          `msgpack:"finger"`
	Metric          Metric          `msgpack:"metric"`
	AffectedVersion *string         `msgpack:"affected_version"`
	Suggestion      *string         `msgpack:"suggestion"`
}

type Finger struct {
	Service  string `msgpack:"service"`
	Version  string `msgpack:"version"`
	Srvproto string `msgpack:"srvproto"`
}

type Metric struct {
	Score           *float64 `msgpack:"score"`
	Vector          *string  `msgpack:"vector"`
	Complexity      *string  `msgpack:"complexity"`
	Privilege       *string  `msgpack:"privilege"`
	Scope           *string  `msgpack:"scope"`
	Maturity        *string  `msgpack:"maturity"`
	Remediation     *string  `msgpack:"remediation"`
	Confidentiality *string  `msgpack:"confidentiality"`
	Integrity       *string  `msgpack:"integrity"`
	Harmness        *string  `msgpack:"harmness"`
	Scale           *int64   `msgpack:"scale"`
}

type ModuleOptionsReq struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	ModuleType string
	ModuleName string
}

type ModuleOptionsRes map[string]struct {
	Type     string      `msgpack:"type"`
	Required bool        `msgpack:"required"`
	Advanced bool        `msgpack:"advanced"`
	Evasion  bool        `msgpack:"evasion"`
	Desc     string      `msgpack:"desc"`
	Default  interface{} `msgpack:"default"`
	Enums    []string    `msgpack:"enums,omitempty"`
}

type ModuleCompatiblePayloadsReq struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	ModuleName string
}

type ModuleCompatiblePayloadsRes struct {
	Payloads []string `msgpack:"payloads"`
}

type ModuleTargetCompatiblePayloadsReq struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	ModuleName string
	ArchNumber uint32
}

type ModuleTargetCompatiblePayloadsRes struct {
	Payloads []string `msgpack:"payloads"`
}

type ModuleCompatibleSessionsReq struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	ModuleName string
}

type ModuleCompatibleSessionsRes struct {
	Sessions []string `msgpack:"sessions"`
}

type ModuleEncodeReq struct {
	_msgpack      struct{} `msgpack:",asArray"`
	Method        string
	Token         string
	Data          string
	EncoderModule string
	Options       map[string]string
}

type ModuleEncodeRes struct {
	Encoded []byte `msgpack:"encoded"`
}

type ModuleExecuteReq struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	ModuleType string
	ModuleName string
	Options    map[string]interface{}
}

type ModuleExecuteRes struct {
	JobId uint32 `msgpack:"job_id"`
}

type ModuleCheckReq struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	ModuleType string
	ModuleName string
	Options    map[string]interface{}
}

type ModuleCheckRes struct {
	JobId uint32 `msgpack:"job_id"`
	UUID  string `msgpack:"uuid"`
}

type ModuleResultsReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
	UUID     string
}

type ModuleResultsRes struct {
	Status string  `msgpack:"status"`
	Error  *string `msgpack:"error"`
	Result *struct {
		Code    string                 `msgpack:"code"`
		Message string                 `msgpack:"message"`
		Reason  *string                `msgpack:"reason"`
		Details map[string]interface{} `msgpack:"details"`
	} `msgpack:"result"`
}

type ModuleAckReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
	UUID     string
}

type ModuleAckRes struct {
	Success bool `msgpack:"success"`
}

type ModuleSourceRes struct {
	Code    string `msgpack:"code"`
	Check   bool   `msgpack:"check"`
	Exploit bool   `msgpack:"exploit"`
	Kind    string `msgpack:"kind"`
}

func (msf *Metasploit) ModuleExploits() (ModuleExploitsRes, error) {
	ctx := &ModuleExploitsReq{
		Method: "module.exploits",
		Token:  msf.token,
	}
	var res ModuleExploitsRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleExploitsRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) ModuleSource(moduleType, moduleName string) (ModuleSourceRes, error) {
	ctx := &ModuleInfoReq{
		Method:     "module.source",
		Token:      msf.token,
		ModuleType: moduleType,
		ModuleName: moduleName,
	}
	var res ModuleSourceRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleSourceRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) ModulePocs() (ModuleExploitsRes, error) {
	ctx := &ModuleExploitsReq{
		Method: "module.pocs",
		Token:  msf.token,
	}
	var res ModuleExploitsRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleExploitsRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) ModuleAuxiliary() (ModuleAuxiliaryRes, error) {
	ctx := &ModuleAuxiliaryReq{
		Method: "module.auxiliary",
		Token:  msf.token,
	}
	var res ModuleAuxiliaryRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleAuxiliaryRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) ModulePost() (ModulePostRes, error) {
	ctx := &ModulePostReq{
		Method: "module.post",
		Token:  msf.token,
	}
	var res ModulePostRes
	if err := msf.send(ctx, &res); err != nil {
		return ModulePostRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) ModulePayloads() (ModulePayloadsRes, error) {
	ctx := &ModulePayloadsReq{
		Method: "module.payloads",
		Token:  msf.token,
	}
	var res ModulePayloadsRes
	if err := msf.send(ctx, &res); err != nil {
		return ModulePayloadsRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) ModuleEncoders() (ModuleEncodersRes, error) {
	ctx := &ModuleEncodersReq{
		Method: "module.encoders",
		Token:  msf.token,
	}
	var res ModuleEncodersRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleEncodersRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) ModuleNops() (ModuleNopsRes, error) {
	ctx := &ModuleNopsReq{
		Method: "module.nops",
		Token:  msf.token,
	}
	var res ModuleNopsRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleNopsRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) ModuleInfo(moduleType, moduleName string) (ModuleInfoRes, error) {
	ctx := &ModuleInfoReq{
		Method:     "module.info",
		Token:      msf.token,
		ModuleType: moduleType,
		ModuleName: moduleName,
	}
	var res ModuleInfoRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleInfoRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) ModuleOptions(moduleType, moduleName string) (ModuleOptionsRes, error) {
	ctx := &ModuleOptionsReq{
		Method:     "module.options",
		Token:      msf.token,
		ModuleType: moduleType,
		ModuleName: moduleName,
	}
	var res ModuleOptionsRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleOptionsRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) ModuleInfoHtml(moduleType, moduleName string) (string, error) {
	ctx := &ModuleOptionsReq{
		Method:     "module.info_html",
		Token:      msf.token,
		ModuleType: moduleType,
		ModuleName: moduleName,
	}
	var res string
	if err := msf.send(ctx, &res); err != nil {
		return "", err
	}
	return res, nil
}

func (msf *Metasploit) ModuleDocumentation(moduleType, moduleName string) (string, error) {
	ctx := &ModuleOptionsReq{
		Method:     "module.documentation",
		Token:      msf.token,
		ModuleType: moduleType,
		ModuleName: moduleName,
	}
	var res string
	if err := msf.send(ctx, &res); err != nil {
		return "", err
	}
	return res, nil
}

func (msf *Metasploit) ModuleCompatiblePayloads(moduleName string) (ModuleCompatiblePayloadsRes, error) {
	ctx := &ModuleCompatiblePayloadsReq{
		Method:     "module.compatible_payloads",
		Token:      msf.token,
		ModuleName: moduleName,
	}
	var res ModuleCompatiblePayloadsRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleCompatiblePayloadsRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) ModuleTargetCompatiblePayloads(moduleName string, targetNumber uint32) (ModuleTargetCompatiblePayloadsRes, error) {
	ctx := &ModuleTargetCompatiblePayloadsReq{
		Method:     "module.target_compatible_payloads",
		Token:      msf.token,
		ModuleName: moduleName,
		ArchNumber: targetNumber,
	}
	var res ModuleTargetCompatiblePayloadsRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleTargetCompatiblePayloadsRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) ModuleCompatibleSessions(moduleName string) (ModuleCompatibleSessionsRes, error) {
	ctx := &ModuleCompatibleSessionsReq{
		Method:     "module.compatible_sessions",
		Token:      msf.token,
		ModuleName: moduleName,
	}
	var res ModuleCompatibleSessionsRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleCompatibleSessionsRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) ModuleEncode(data, encoderModule string, moduleOptions map[string]string) (ModuleEncodeRes, error) {
	ctx := &ModuleEncodeReq{
		Method:        "module.encode",
		Token:         msf.token,
		Data:          data,
		EncoderModule: encoderModule,
		Options:       moduleOptions,
	}
	var res ModuleEncodeRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleEncodeRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) ModuleExecute(moduleType, moduleName string, moduleOptions map[string]interface{}) (ModuleExecuteRes, error) {
	ctx := &ModuleExecuteReq{
		Method:     "module.execute",
		Token:      msf.token,
		ModuleType: moduleType,
		ModuleName: moduleName,
		Options:    moduleOptions,
	}
	var res ModuleExecuteRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleExecuteRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) ModuleCheck(moduleType, moduleName string, moduleOptions map[string]interface{}) (ModuleCheckRes, error) {
	ctx := &ModuleCheckReq{
		Method:     "module.check",
		Token:      msf.token,
		ModuleType: moduleType,
		ModuleName: moduleName,
		Options:    moduleOptions,
	}
	var res ModuleCheckRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleCheckRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) ModuleResults(uuid string) (ModuleResultsRes, error) {
	ctx := &ModuleResultsReq{
		Method: "module.results",
		Token:  msf.token,
		UUID:   uuid,
	}
	var res ModuleResultsRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleResultsRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) ModuleAck(uuid string) (ModuleAckRes, error) {
	ctx := &ModuleAckReq{
		Method: "module.ack",
		Token:  msf.token,
		UUID:   uuid,
	}
	var res ModuleAckRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleAckRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) GetModuleRequires(moduleType, moduleName string) ([]string, error) {
	var returnValues []string

	options, err := msf.ModuleOptions(moduleType, moduleName)

	if err != nil {
		return nil, err
	}

	for key, option := range options {
		if option.Required {
			returnValues = append(returnValues, key)
		}
	}
	return returnValues, nil
}
