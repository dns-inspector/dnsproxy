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
	"sync"
	"time"

	"github.com/ecnepsnai/logtic"
	"github.com/ecnepsnai/zbx"
)

var keyToItemIdMap = map[string]int{
	"panic.recover":     -1,
	"query.doh.error":   -1,
	"query.doh.forward": -1,
	"query.doq.error":   -1,
	"query.doq.forward": -1,
	"query.dot.error":   -1,
	"query.dot.forward": -1,
	"server.state":      -1,
}

var valMap = map[int]uint{}
var valLock = &sync.Mutex{}
var session *zbx.ActiveSession
var log = logtic.Log.Connect("zabbix")

func Setup(serverName, zabbixHost string) {
	var items []zbx.SupportedItem
	var s *zbx.ActiveSession
	var err error
	for {
		s, items, err = zbx.StartActive(serverName, zabbixHost)
		if err != nil {
			log.PError("Error connecting to zabbix server, will try again in 1 minute", map[string]any{
				"server": zabbixHost,
				"error":  err.Error(),
			})
			time.Sleep(60 * time.Second)
		} else {
			log.Debug("Connecting to zabbix server with %d items", len(items))
			break
		}
	}

	for _, item := range items {
		if _, known := keyToItemIdMap[item.Key]; known {
			keyToItemIdMap[item.Key] = item.ItemId
		}
	}

	for key, id := range keyToItemIdMap {
		if id == -1 {
			log.Error("No active item with key '%s' found for zabbix host '%s'. This metric will not be sent to the server.", key, zabbixHost)
		}
	}

	session = s
	StartSendLoop()
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
	// server.state is always 1
	strValues[keyToItemIdMap["server.state"]] = "1"

	if err := session.Send(strValues); err != nil {
		log.PError("Error sending values to zabbix server", map[string]any{
			"error": err.Error(),
		})
		return
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
