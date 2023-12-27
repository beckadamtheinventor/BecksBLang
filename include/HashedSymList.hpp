#ifndef __HASHED_SYM_LIST_HPP__
#define __HASHED_SYM_LIST_HPP__

#include <stdint.h>
#include <stdexcept>
#include <string.h>

namespace HashedSymList {
    constexpr static const uint8_t hashTable[256] = {
        182, 200, 228, 21, 157, 131, 50, 203, 36, 224, 66, 15, 208,
        242, 26, 63, 134, 141, 10, 120, 219, 30, 126, 49, 5,
        249, 152, 173, 156, 103, 184, 59, 189, 168, 221, 105,
        108, 140, 23, 198, 174, 187, 92, 178, 148, 181, 222,
        169, 95, 82, 87, 27, 34, 217, 97, 51, 67, 243, 235,
        88, 145, 238, 255, 11, 133, 185, 16, 58, 229, 241,
        206, 188, 146, 209, 128, 8, 191, 252, 93, 234, 81, 94,
        2, 193, 130, 122, 0, 207, 28, 190, 65, 110, 104, 47,
        70, 132, 12, 216, 25, 129, 40, 163, 86, 159, 79, 33,
        199, 56, 61, 31, 165, 83, 14, 239, 204, 76, 170,
        99, 139, 137, 106, 113, 175, 55, 32, 78, 62, 111,
        6, 246, 135, 107, 109, 19, 210, 225, 172, 112, 245,
        171, 230, 71, 151, 37, 153, 100, 29, 162, 20, 80,
        195, 42, 9, 202, 57, 45, 197, 177, 154, 1, 53,
        90, 48, 117, 214, 44, 205, 77, 119, 136, 248,
        253, 91, 155, 85, 84, 102, 236, 244, 212, 22,
        218, 254, 213, 17, 114, 147, 226, 13, 18, 115, 24,
        121, 98, 237, 227, 186, 196, 144, 46, 233, 123,
        247, 68, 7, 179, 43, 89, 231, 52, 64, 150, 75,
        232, 73, 240, 211, 250, 194, 176, 160, 251, 138,
        201, 118, 220, 96, 41, 164, 158, 54, 35, 60, 3,
        124, 223, 166, 4, 101, 116, 38, 143, 39, 72, 192,
        74, 215, 180, 149, 125, 161, 127, 69, 142, 183, 167
    };

    static uint32_t Hash(const char *s) {
        uint8_t hash[4] = {0};
        uint8_t j = 0;
        for (size_t i=0; s[i+j]; i+=4) {
            for (j=0; j<4 && s[i]; j++, i++) {
                hash[j] = hashTable[hash[j] ^ s[i+j]];
            }
        }
        return *(uint32_t*)hash;
    }

    template<class V>
    class HashedSymList {
        constexpr static const size_t MIN_NUM_ENTRIES = 16;
        public:
        class Symbol {
            public:
            uint32_t hash;
            char *key;
            V value;
            Symbol(uint32_t hash, char *key) {
                this->key = key;
                this->hash = hash;
            }
            Symbol(char *key) : Symbol(Hash(key), key) {};
            Symbol() : Symbol(0, nullptr) {};

            Symbol& operator=(const Symbol& sym) {
                hash = sym.hash;
                key = sym.key;
                value = sym.value;
            }
            V& operator=(const V& val) {
                value = val;
            }

            operator V() const {return value;}
        };

        private:
        Symbol *entries = nullptr;
        size_t max_entries;

        public:

        HashedSymList() : HashedSymList(MIN_NUM_ENTRIES) {}
        HashedSymList(size_t max) {
            max_entries = max;
            if (max > 0) {
                entries = new Symbol[max];
            } else {
                entries = nullptr;
            }
        }

        void Resize(size_t size) {
            Symbol *newmembers = new Symbol[size];
            size_t j = 0;
            for (size_t i = 0; i < max_entries; i++) {
                if (entries[i].key == nullptr) {
                    newmembers[j++] = entries[i];
                }
            }
            while (j < size) {
                entries[j++].key = nullptr;
            }
            max_entries = size;
            delete [] entries;
            entries = newmembers;
        }

        void Add(const char *key, V value) {
            for (size_t i = 0; i < max_entries; i++) {
                if (entries[i].key == nullptr) {
                    entries[i].hash = Hash(key);
                    entries[i].key = key;
                    entries[i].value = value;
                    return;
                }
            }
            Resize(max_entries + MIN_NUM_ENTRIES);
            size_t j = FindFirstEmptyIndex();
            entries[j].hash = Hash(key);
            entries[j].key = key;
            entries[j].value = value;
        }

        void Remove(const char *key) {
            Symbol& sym = FindSym(key);
            sym.name = nullptr;
        }

        size_t FindSymIndex(const char *key) {
            uint32_t hash = Hash(key);
            for (size_t i = 0; i < max_entries; i++) {
                if (entries[i].key != nullptr) {
                    if (entries[i].hash == hash) {
                        if (!strcmp(entries[i].key, key)) {
                            return i;
                        }
                    }
                }
            }
            return -1;
        }

        bool Contains(const char *key) {
            return (FindSymIndex(key) != -1);
        }

        size_t Length() {
            size_t l = 0;
            for (size_t i = 0; i < max_entries; i++) {
                if (entries[i].key != nullptr) {
                    l++;
                }
            }
            return l;
        }

        size_t FindFirstEmptyIndex() {
            for (size_t i = 0; i < max_entries; i++) {
                if (entries[i].key == nullptr) {
                    return i;
                }
            }
            size_t n = max_entries;
            Resize(max_entries + MIN_NUM_ENTRIES);
            return n;
        }

        Symbol& Get(size_t i) {
            for (size_t j = 0; j < max_entries; j++) {
                if (entries[j].key != nullptr) {
                    i--;
                    if (i <= 0) {
                        return entries[j];
                    }
                }
            }
            return entries[FindFirstEmptyIndex()];
        }

        Symbol& FindSym(const char *key) {
            size_t i = FindSymIndex(key);
            if (i == -1) {
                return entries[FindFirstEmptyIndex()];
            }
            return entries[i];
        }

        char *Keys(size_t i) {
            return Get(i).key;
        }

        V& Values(size_t i) {
            return Get(i).value;
        }

        Symbol& NextSym(const char *key) {
            size_t i = FindSymIndex(key);
            if (i == -1) {
                return -1;
            }
            return NextSym(i);
        }

        Symbol& NextSym(size_t i) {
            if (i+1 >= max_entries) {
                return new Symbol;
            }
            return entries[i+1];
        }

        Symbol& operator[](const char *key) {
            return FindSym(key);
        }

        Symbol& operator[](size_t i) {
            return Get(i);
        }
    };
}

#endif