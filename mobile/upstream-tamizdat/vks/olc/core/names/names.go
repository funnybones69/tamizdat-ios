// Package names generates human-looking display names for SFU peers so a
// tunnel participant is indistinguishable from an ordinary attendee.
//
// The generator is gender-aware: every female first name is paired with the
// feminine form of the surname ("Оксана Баранова", never "Оксана Баранов").
// A minority of names use realistic casual styles seen in real calls —
// transliterated latin ("dmitriy smirnov"), nicknames ("Дима С."), and
// abbreviated surnames ("Дмитрий Смирн.").
//
// The embedded dictionaries are always available; LoadNameFiles replaces them
// with on-disk ones when an operator wants a different pool (those override
// files are used verbatim as "First Last" pairs).
package names

import (
	"crypto/rand"
	_ "embed"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync/atomic"
)

//go:embed data/names
var embeddedNames string

//go:embed data/surnames
var embeddedSurnames string

// ErrEmptyDictionary reports a dictionary file that contains no usable entries.
var ErrEmptyDictionary = errors.New("names: dictionary file is empty")

// dictionaries is swapped atomically so LoadNameFiles can run while other
// goroutines call Generate.
//
//nolint:gochecknoglobals // process-wide dictionary pool, swapped atomically
var dictionaries atomic.Pointer[pool]

type pool struct {
	first []string
	last  []string
}

// firstName carries the gender and the latin/nickname spellings used by the
// casual display-name styles.
type firstName struct {
	ru     string
	latin  string
	nick   string
	female bool
}

// surname pairs the Russian form (masculine base) with its latin spelling.
type surname struct {
	ru    string
	latin string
}

var firstNames = []firstName{
	// male
	{"Александр", "aleksandr", "Саша", false},
	{"Сергей", "sergey", "Серёга", false},
	{"Дмитрий", "dmitriy", "Дима", false},
	{"Андрей", "andrey", "Андрюха", false},
	{"Алексей", "alexey", "Лёха", false},
	{"Максим", "maksim", "Макс", false},
	{"Иван", "ivan", "Ваня", false},
	{"Михаил", "mikhail", "Миша", false},
	{"Артём", "artyom", "Тёма", false},
	{"Никита", "nikita", "Ник", false},
	{"Кирилл", "kirill", "Кир", false},
	{"Роман", "roman", "Рома", false},
	{"Денис", "denis", "Дэн", false},
	{"Павел", "pavel", "Паша", false},
	{"Владимир", "vladimir", "Вова", false},
	{"Егор", "egor", "Егор", false},
	{"Антон", "anton", "Тоха", false},
	{"Игорь", "igor", "Игорёк", false},
	{"Олег", "oleg", "Олег", false},
	{"Юрий", "yuri", "Юра", false},
	// female
	{"Елена", "elena", "Лена", true},
	{"Ольга", "olga", "Оля", true},
	{"Анна", "anna", "Аня", true},
	{"Мария", "maria", "Маша", true},
	{"Наталья", "natalya", "Ната", true},
	{"Ирина", "irina", "Ира", true},
	{"Светлана", "svetlana", "Света", true},
	{"Татьяна", "tatyana", "Таня", true},
	{"Юлия", "yuliya", "Юля", true},
	{"Екатерина", "ekaterina", "Катя", true},
	{"Дарья", "darya", "Даша", true},
	{"Анастасия", "anastasia", "Настя", true},
	{"Полина", "polina", "Поля", true},
	{"Виктория", "viktoriya", "Вика", true},
	{"Ксения", "ksenia", "Ксюша", true},
	{"Елизавета", "elizaveta", "Лиза", true},
	{"Александра", "alexandra", "Саша", true},
	{"Валерия", "valeriya", "Лера", true},
	{"София", "sofia", "Соня", true},
	{"Алина", "alina", "Алина", true},
}

var surnames = []surname{
	{"Иванов", "ivanov"},
	{"Смирнов", "smirnov"},
	{"Кузнецов", "kuznetsov"},
	{"Попов", "popov"},
	{"Васильев", "vasiliev"},
	{"Петров", "petrov"},
	{"Соколов", "sokolov"},
	{"Михайлов", "mikhailov"},
	{"Новиков", "novikov"},
	{"Фёдоров", "fedorov"},
	{"Морозов", "morozov"},
	{"Волков", "volkov"},
	{"Алексеев", "alekseev"},
	{"Лебедев", "lebedev"},
	{"Семёнов", "semenov"},
	{"Егоров", "egorov"},
	{"Павлов", "pavlov"},
	{"Козлов", "kozlov"},
	{"Степанов", "stepanov"},
	{"Николаев", "nikolaev"},
	{"Орлов", "orlov"},
	{"Захаров", "zakharov"},
	{"Белов", "belov"},
	{"Медведев", "medvedev"},
	{"Баранов", "baranov"},
	{"Киселёв", "kiselev"},
	{"Максимов", "maksimov"},
	{"Жуков", "zhukov"},
	{"Крылов", "krylov"},
	{"Комаров", "komarov"},
	{"Тихомиров", "tikhomirov"},
	{"Гусев", "gusev"},
	{"Соловьёв", "solovyov"},
	{"Быков", "bykov"},
	{"Зайцев", "zaitsev"},
	{"Тарасов", "tarasov"},
	{"Карпов", "karpov"},
	{"Григорьев", "grigoriev"},
	{"Фролов", "frolov"},
	{"Данилов", "danilov"},
}

//nolint:gochecknoinits // seeds the embedded dictionaries before first use
func init() {
	first := parseLines(embeddedNames)
	last := parseLines(embeddedSurnames)
	if len(first) == 0 {
		first = []string{"Александр", "Мария"}
	}
	if len(last) == 0 {
		last = []string{"Иванов"}
	}
	p := &pool{first: first, last: last}
	dictionaries.Store(p)
	embeddedPool.Store(p)
}

func parseLines(raw string) []string {
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln != "" {
			out = append(out, ln)
		}
	}
	return out
}

func loadFile(path string) ([]string, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path is explicit operator configuration
	if err != nil {
		return nil, fmt.Errorf("names: read %s: %w", path, err)
	}
	entries := parseLines(string(raw))
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrEmptyDictionary, path)
	}
	return entries, nil
}

// LoadNameFiles replaces the embedded dictionaries with the given files.
// Unlike the embedded fallback these are operator-supplied, so an unreadable
// or empty file is reported instead of being silently ignored. Names from an
// override pool are used verbatim as "First Last" pairs.
func LoadNameFiles(firstPath, lastPath string) error {
	first, err := loadFile(firstPath)
	if err != nil {
		return err
	}

	last, err := loadFile(lastPath)
	if err != nil {
		return err
	}

	dictionaries.Store(&pool{first: first, last: last})

	return nil
}

// Generate returns a random realistic display name. Most names are proper
// gender-agreed Russian full names; a minority use casual styles common in
// real calls (latin transliteration, nicknames, abbreviated surnames).
func Generate() string {
	if p := dictionaries.Load(); p != nil && len(p.first) > 0 && len(p.last) > 0 {
		// Operator override dictionaries: use them verbatim.
		if !isEmbedded(p) {
			return p.first[randomIndex(len(p.first))] + " " + p.last[randomIndex(len(p.last))]
		}
	}

	who := firstNames[randomIndex(len(firstNames))]
	sur := surnames[randomIndex(len(surnames))]

	switch roll := randomIndex(100); {
	case roll < 58:
		return proper(who, sur)
	case roll < 72:
		return latin(who, sur)
	case roll < 84:
		return nickWithInitial(who, sur)
	case roll < 92:
		return who.nick
	default:
		return abbreviate(who, sur)
	}
}

// proper builds "Имя Фамилия" with correct gender agreement.
func proper(who firstName, sur surname) string {
	return who.ru + " " + agree(who, sur.ru)
}

// agree returns the surname in the grammatically correct gender form.
func agree(who firstName, last string) string {
	if !who.female {
		return last
	}
	switch {
	case strings.HasSuffix(last, "ов"), strings.HasSuffix(last, "ев"),
		strings.HasSuffix(last, "ёв"), strings.HasSuffix(last, "ин"),
		strings.HasSuffix(last, "ын"):
		return last + "а"
	case strings.HasSuffix(last, "ий"):
		return last[:len(last)-2] + "ая"
	case strings.HasSuffix(last, "ый"):
		return last[:len(last)-2] + "ая"
	default:
		return last + "а"
	}
}

// latin builds "dmitriy smirnov" / "alina sokolova" style lowercase latin
// names; feminine surnames get the -a ending as Russians transliterate them.
func latin(who firstName, sur surname) string {
	last := sur.latin
	if who.female {
		last += "a"
	}
	return who.latin + " " + last
}

// nickWithInitial builds "Дима С." style nicknames.
func nickWithInitial(who firstName, sur surname) string {
	initial := strings.ToUpper(string([]rune(sur.ru)[0]))
	return who.nick + " " + initial + "."
}

// abbreviate builds "Дмитрий Смирн." style abbreviated surnames. The cut is
// applied to the masculine base so feminine forms do not end on a dangling
// "Тарасо."; surnames short enough that the cut would not shorten them are
// kept whole (gender-agreed).
func abbreviate(who firstName, sur surname) string {
	base := []rune(sur.ru)
	if len(base) > 7 {
		return who.ru + " " + string(base[:6]) + "."
	}
	return who.ru + " " + agree(who, sur.ru)
}

// isEmbedded reports whether p is (still) the embedded dictionary. The
// pointer comparison is safe because init() stores exactly one pointer and
// LoadNameFiles stores a fresh one on every call.
func isEmbedded(p *pool) bool {
	if p == nil {
		return true
	}
	return len(p.first) > 0 && len(p.last) > 0 && p == embeddedPool.Load()
}

// embeddedPool remembers the initial dictionary so isEmbedded can tell it
// apart from an operator override.
//
//nolint:gochecknoglobals // set once in init, read-only afterwards
var embeddedPool atomic.Pointer[pool]

func randomIndex(limit int) int {
	if limit <= 1 {
		return 0
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(limit)))
	if err != nil {
		return 0
	}

	return int(n.Int64())
}
