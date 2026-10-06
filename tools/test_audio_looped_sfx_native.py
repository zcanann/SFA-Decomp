#!/usr/bin/env python3
"""Check production looped-sound bookkeeping against a record-based native model."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;
/* Only this engine-owned field is consumed; its host offset is deliberately different. */
typedef struct GameObject { void* hostPayload; u32 objectFlags; } GameObject;
#define OBJECT_OBJFLAG_FREED 0x40
static void Sfx_PlayFromObject(GameObject*, u16);
static void Sfx_StopFromObject(GameObject*, u16);
static s32 Sfx_IsPlayingFromObject(GameObject*, u16);
'''
CHECKS = r'''
typedef struct { GameObject* object; u16 id; u8 flags; } Record;
typedef struct { int kind; GameObject* object; u16 id; int count; } Event;
static Record expected[128];
static int length, eventCount, eventIndex, checks;
static Event events[512];
static GameObject objects[140];
static u32 randomState = 0x94157213;
static u32 randomWord(void) {
    randomState ^= randomState << 13; randomState ^= randomState >> 17; randomState ^= randomState << 5;
    return randomState;
}
static void expect(int kind, GameObject* object, u16 id) {
    assert(eventCount < 512); events[eventCount++] = (Event){kind,object,id,length};
}
static void observe(int kind, GameObject* object, u16 id) {
    assert(eventIndex < eventCount); Event e = events[eventIndex++];
    assert(e.kind == kind && e.object == object && e.id == id && e.count == gSfxLoopedObjectSoundCount);
}
static int playing(GameObject* object, u16 id) { return ((uintptr_t)object/8 + id)%3 != 0; }
static void Sfx_PlayFromObject(GameObject* object, u16 id) { observe(1,object,id); }
static void Sfx_StopFromObject(GameObject* object, u16 id) { observe(2,object,id); }
static s32 Sfx_IsPlayingFromObject(GameObject* object, u16 id) {
    observe(3,object,id); return playing(object,id);
}
static void erase(int index) {
    length--;
    for (int j = index; j < length; j++) expected[j] = expected[j+1];
}
static void model(int operation, GameObject* object, u16 id, u16 limit) {
    if (operation == 0) { length = 0; return; }
    if (operation == 1 || operation == 2 || operation == 6) {
        int same = 0;
        for (int j = 0; j < length; j++) {
            if (expected[j].id == id) {
                same++;
                if (expected[j].object == object) {
                    if (operation != 1) expected[j].flags |= 3;
                    return;
                }
            }
        }
        if (length == 128 || (operation == 2 && limit && same > limit)) return;
        expected[length++] = (Record){object,id,0}; expect(1,object,id);
        if (operation != 1) expected[length-1].flags = 3;
        return;
    }
    if (operation == 3 || operation == 4) {
        for (int j = length-1; j >= 0; j--) {
            if (expected[j].object == object && (operation == 3 || expected[j].id == id)) {
                if (operation == 3) expect(2,object,expected[j].id);
                erase(j);
                if (operation == 4) expect(2,object,id);
                return;
            }
        }
        return;
    }
    assert(operation == 5);
    for (int j = length-1; j >= 0; j--) {
        Record r = expected[j];
        if (((r.flags & 1) && !(r.flags & 2)) || (r.object && (r.object->objectFlags & 0x40))) {
            expect(2,r.object,r.id); erase(j);
        } else expected[j].flags &= ~2;
    }
    for (int j = 0; j < length; j++) {
        Record r = expected[j]; expect(3,r.object,r.id);
        if (!playing(r.object,r.id)) expect(1,r.object,r.id);
    }
}
static void step(int operation, GameObject* object, u16 id, u16 limit) {
    eventCount = eventIndex = 0; model(operation,object,id,limit);
    switch (operation) {
    case 0: Sfx_ClearLoopedObjectSounds(); break;
    case 1: Sfx_AddLoopedObjectSound(object,id); break;
    case 2: Sfx_KeepAliveLoopedObjectSoundLimited(object,id,limit); break;
    case 3: Sfx_RemoveLoopedObjectSoundForObject(object); break;
    case 4: Sfx_RemoveLoopedObjectSound(object,id); break;
    case 5: Sfx_UpdateLoopedObjectSounds(); break;
    case 6: Sfx_KeepAliveLoopedObjectSound(object,id); break;
    }
    assert(eventIndex == eventCount && gSfxLoopedObjectSoundCount == length);
    for (int j = 0; j < length; j++) {
        assert(gSfxLoopedObjectSoundObjects[j] == expected[j].object);
        assert(gSfxLoopedObjectSoundIds[j] == expected[j].id);
        assert(gSfxLoopedObjectSoundFlags[j] == expected[j].flags);
    }
    checks++;
}
int main(void) {
    assert(sizeof(void*) == 8 && (uintptr_t)objects > UINT32_MAX);
    /* Empty lists, full capacity, duplicates, all compaction positions and reused slots. */
    step(0,NULL,0,0); step(5,NULL,0,0); step(3,NULL,0,0); step(4,NULL,0,0);
    for (int j = 0; j < 128; j++) step(1,&objects[j],j,0);
    step(1,&objects[139],999,0); step(1,&objects[0],0,0);
    step(4,&objects[0],0,0); step(4,&objects[64],64,0); step(4,&objects[127],127,0);
    step(6,NULL,65535,0); step(6,NULL,65535,0); step(5,NULL,0,0); step(5,NULL,0,0);
    step(0,NULL,0,0);
    /* The retail limit permits limit+1 instances; zero means unlimited. */
    step(2,&objects[0],21,1); step(2,&objects[1],21,1); step(2,&objects[2],21,1);
    assert(length == 2); step(2,&objects[0],21,1);
    step(6,&objects[2],21,0); objects[1].objectFlags = 0x40; step(5,NULL,0,0);
    step(3,&objects[0],0,0); step(4,&objects[2],21,0); step(5,NULL,0,0);
    for (int j = 0; j < 5000; j++) {
        u32 word = randomWord();
        GameObject* object = word%17 ? &objects[word%140] : NULL;
        int operation = 1 + (word>>9)%6;
        if (j%97 == 0) objects[(word>>16)%140].objectFlags ^= 0x40;
        if (j%499 == 0) step(0,NULL,0,0);
        step(operation,object,(word>>18)%37,(word>>26)%4);
    }
    printf("%d looped-sound operations agree with the independent model\n",checks);
}
'''


def harness():
    source = (ROOT / 'src/main/audio_looped_sfx.c').read_text()
    source = re.sub(r'^#include[^\n]*\n', '', source, flags=re.M)
    header = (ROOT / 'include/main/audio/sfx_looped_object_api.h').read_text()
    header = re.sub(r'^#include[^\n]*\n', '', header, flags=re.M)
    return '\n'.join([PRELUDE, header, source, CHECKS])


class LoopedSfxNativeTest(unittest.TestCase):
    def test_complete_tu(self):
        compiler = shutil.which('clang') or shutil.which('cc')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix='looped-sfx-') as directory:
            path = Path(directory)
            source = path / 'loops.c'
            source.write_text(harness())
            for optimization in ['-O0', '-O2']:
                with self.subTest(optimization=optimization):
                    exe = path / 'loops'
                    subprocess.run([compiler, '-std=c11', optimization, '-g', '-Wall', '-Wextra',
                                    '-Werror', '-Wno-sign-compare', '-fsanitize=address,undefined',
                                    '-fno-common', '-fno-omit-frame-pointer', str(source), '-o', str(exe)],
                                   check=True, timeout=30)
                    subprocess.run([str(exe)], check=True, timeout=30)


if __name__ == '__main__':
    unittest.main()
