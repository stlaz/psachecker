package admission

import (
	"sort"

	psapi "k8s.io/pod-security-admission/api"
)

type OrderedStringToPSALevelMap struct {
	ordered     bool
	internalMap map[string]psapi.Level
	keys        sort.StringSlice
}

func NewOrderedStringToPSALevelMap(m map[string]psapi.Level) *OrderedStringToPSALevelMap {
	ret := &OrderedStringToPSALevelMap{
		ordered:     true,
		internalMap: make(map[string]psapi.Level),
		keys:        make([]string, 0),
	}

	if len(m) != 0 {
		ret.ordered = false
		ret.internalMap = m
		for k := range m {
			ret.keys = append(ret.keys, k)
		}
	}

	return ret
}

func (m *OrderedStringToPSALevelMap) Set(k string, v psapi.Level) {
	if _, ok := m.internalMap[k]; !ok {
		m.ordered = false
		m.keys = append(m.keys, k)
	}
	m.internalMap[k] = v
}

func (m *OrderedStringToPSALevelMap) Get(k string) psapi.Level {
	return m.internalMap[k]
}

func (m *OrderedStringToPSALevelMap) Keys() []string {
	ret := make([]string, len(m.keys))

	if !m.ordered {
		m.keys.Sort()
		m.ordered = true
	}

	copy(ret, m.keys)
	return ret
}
