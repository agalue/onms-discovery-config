package main

import (
	"encoding/xml"
	"fmt"
	"testing"
)

func TestParseEventLog(t *testing.T) {
	// The reference config was created using send-event.pl
	referenceConfig := `
	<log>
	<events>
	<event >
	<uei>uei.opennms.org/internal/reloadDaemonConfig</uei>
	<source>perl_send_event</source>
	<time>2021-11-03T20:08:39+00:00</time>
	<host>agalue-mbp.local</host>
	<parms>
		<parm>
		<parmName><![CDATA[daemonName]]></parmName>
		<value type="string" encoding="text"><![CDATA[Discovery]]></value>
		</parm>
	</parms>
	</event>
	</events>
	</log>
	`
	log := new(Log)
	if err := xml.Unmarshal([]byte(referenceConfig), log); err != nil {
		t.Errorf("cannot parse configuration: %v", err)
	}
	output, _ := xml.MarshalIndent(log, "", "  ")
	fmt.Println(string(output))

	// Validating content
	if len(log.Events) != 1 {
		t.Errorf("the log should have one event")
	}
	if log.Events[0].UEI != "uei.opennms.org/internal/reloadDaemonConfig" {
		t.Errorf("the event has a wrong UEI")
	}
	if len(log.Events[0].Parameters) != 1 {
		t.Errorf("the event should have one parameter")
	}
	if log.Events[0].Parameters[0].Name != "daemonName" {
		t.Errorf("the event parameter name is wrong")
	}
	if log.Events[0].Parameters[0].Value.Content != "Discovery" {
		t.Errorf("the event parameter value is wrong")
	}
}

func TestAddEvent(t *testing.T) {
	log := new(Log)
	log.Add(Event{UEI: "uei.opennms.org/test1"})
	log.Add(Event{UEI: "uei.opennms.org/test2"})
	if len(log.Events) != 2 {
		t.Errorf("the log should have two events")
	}
}
