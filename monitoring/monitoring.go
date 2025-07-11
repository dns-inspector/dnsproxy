/*
DNSProxy
Copyright (C) 2024 Ian Spence

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package monitoring

import (
	"fmt"
	"maps"
	"os"
	"sync"
	"time"

	"github.com/ecnepsnai/zbx"
)

var keyToItemIdMap = map[string]int{
	"panic.recover":     -1,
	"query.doh.forward": -1,
	"query.dot.forward": -1,
	"query.doq.forward": -1,
	"query.doh.error":   -1,
	"query.dot.error":   -1,
	"query.doq.error":   -1,
}

var valMap = map[int]uint{}
var valLock = &sync.Mutex{}
var session *zbx.ActiveSession

func Setup(serverName, zabbixHost string) error {
	s, items, err := zbx.StartActive(serverName, zabbixHost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to zabbix server %s: %s\n", zabbixHost, err.Error())
		return err
	}

	for _, item := range items {
		if _, known := keyToItemIdMap[item.Key]; known {
			keyToItemIdMap[item.Key] = item.ItemId
		}
	}

	for key, id := range keyToItemIdMap {
		if id == -1 {
			fmt.Fprintf(os.Stderr, "No active item with key '%s' found for zabbix host '%s'. This metric will not be sent to the server.\n", key, zabbixHost)
		}
	}

	session = s
	return nil
}

func Send() {
	if session == nil {
		return
	}

	valLock.Lock()
	values := maps.Clone(valMap)
	valMap = map[int]uint{}
	valLock.Unlock()

	strValues := map[int]string{}
	// Set all items to zero
	for _, id := range keyToItemIdMap {
		strValues[id] = "0"
	}
	// Populate items with a values
	for id, value := range values {
		strValues[id] = fmt.Sprintf("%d", value)
	}
	// agent.ping is always 1
	strValues[keyToItemIdMap["agent.ping"]] = "1"

	if err := session.Send(strValues); err != nil {
		fmt.Fprintf(os.Stderr, "Error sending stats to zabbix server: %s\n", err.Error())
	}
}

func StartSendLoop() {
	for {
		time.Sleep(60 * time.Second)
		Send()
	}
}

func incrementValue(key string) {
	if session == nil {
		return
	}

	id := keyToItemIdMap[key]
	valLock.Lock()
	v := valMap[id]
	v++
	valMap[id] = v
	valLock.Unlock()
}

func RecordPanicRecover() {
	incrementValue("panic.recover")
}

func RecordQueryDohForward() {
	incrementValue("query.doh.forward")
}

func RecordQueryDotForward() {
	incrementValue("query.dot.forward")
}

func RecordQueryDoqForward() {
	incrementValue("query.doq.forward")
}

func RecordQueryDohError() {
	incrementValue("query.doh.error")
}

func RecordQueryDotError() {
	incrementValue("query.dot.error")
}

func RecordQueryDoqError() {
	incrementValue("query.doq.error")
}
