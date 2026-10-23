package accessory

// Service types.
const (
	ServiceAccessoryInformation = "3E"
	ServiceProtocolInformation  = "A2"
	ServiceLightbulb            = "43"
	ServiceSwitch               = "49"
	ServiceOutlet               = "47"
	ServiceTemperatureSensor    = "8A"
	ServiceHumiditySensor       = "82"
	ServiceContactSensor        = "80"
	ServiceMotionSensor         = "85"
)

// Category tells controller what kind of accessory it is, e.g. for its icon.
type Category int

const (
	CategoryOther              Category = 1
	CategoryBridge             Category = 2
	CategoryFan                Category = 3
	CategoryGarageDoor         Category = 4
	CategoryLightbulb          Category = 5
	CategoryDoorLock           Category = 6
	CategoryOutlet             Category = 7
	CategorySwitch             Category = 8
	CategoryThermostat         Category = 9
	CategorySensor             Category = 10
	CategoryWindow             Category = 13
	CategoryProgrammableSwitch Category = 15
)

// Info describes accessory in its information service.
type Info struct {
	Name         string
	Manufacturer string
	Model        string
	SerialNumber string
	Firmware     string // e.g. "1.0.0"
}

// NewService returns service of type with characteristics.
func NewService(typ string, chars ...*Characteristic) *Service {
	return &Service{Type: typ, Characteristics: chars}
}

// NewInfoService returns accessory information service, every accessory needs one.
// Writes to its Identify characteristic call Config.OnIdentify.
func NewInfoService(info Info) *Service {
	return NewService(ServiceAccessoryInformation,
		NewCharacteristic("14", FormatBool, PermWrite, false), // Identify
		readOnly("20", info.Manufacturer),
		readOnly("21", info.Model),
		readOnly("23", info.Name),
		readOnly("30", info.SerialNumber),
		readOnly("52", info.Firmware),
	)
}

// NewProtocolInfoService returns protocol information service with HAP version.
func NewProtocolInfoService() *Service {
	return NewService(ServiceProtocolInformation, readOnly("37", "1.1.0"))
}

func readOnly(typ, value string) *Characteristic {
	return NewCharacteristic(typ, FormatString, PermRead, value)
}

// NewName returns name characteristic of service.
func NewName(name string) *Characteristic {
	return readOnly("23", name)
}

// NewOn returns on/off state of lightbulb, switch or outlet.
func NewOn() *Characteristic {
	return NewCharacteristic("25", FormatBool, PermRead|PermWrite|PermEvents, false)
}

// NewBrightness returns brightness in percent.
func NewBrightness() *Characteristic {
	return NewCharacteristic("8", FormatInt, PermRead|PermWrite|PermEvents, 100).
		WithRange(0, 100, 1).WithUnit("percentage")
}

// NewOutletInUse returns whether something is plugged into outlet.
func NewOutletInUse() *Characteristic {
	return NewCharacteristic("26", FormatBool, PermRead|PermEvents, false)
}

// NewCurrentTemperature returns temperature in degrees celsius.
func NewCurrentTemperature() *Characteristic {
	return NewCharacteristic("11", FormatFloat, PermRead|PermEvents, 0.0).
		WithRange(-270, 100, 0.1).WithUnit("celsius")
}

// NewCurrentHumidity returns relative humidity in percent.
func NewCurrentHumidity() *Characteristic {
	return NewCharacteristic("10", FormatFloat, PermRead|PermEvents, 0.0).
		WithRange(0, 100, 1).WithUnit("percentage")
}

// NewContactState returns 0 when contact is detected, 1 when not.
func NewContactState() *Characteristic {
	return NewCharacteristic("6A", FormatUint8, PermRead|PermEvents, 0).WithRange(0, 1, 1)
}

// NewMotionDetected returns whether motion is detected.
func NewMotionDetected() *Characteristic {
	return NewCharacteristic("22", FormatBool, PermRead|PermEvents, false)
}
