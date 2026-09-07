"""Exercise native sequencer storage, note recycling, and public controls."""
import ctypes
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from brute_match import find_function_body
from tricky_object_compare import read_object

ROOT = Path(__file__).resolve().parents[1]


def function(source, name):
    start, end = find_function_body(source, name)
    declaration = re.search(r'^\w[^\n]*\b' + re.escape(name) + r'\([^;]*$', source[:start], re.M)
    if declaration is None:
        raise ValueError('missing definition: ' + name)
    return source[declaration.start():end + 1]


class SequenceLayoutTests(unittest.TestCase):
    def test_native_arrays(self):
        path = ROOT / 'build/GSAE01/src/musyx/runtime/seq.o'
        if not path.exists():
            self.skipTest('build the sequencer source object first')
        obj = read_object(path)
        self.assertEqual(obj.sections['.bss'][3], 0xD840)
        for name, offset, size in [('seqNote', 0, 0x1400), ('seqInstance', 0x1400, 0xC340),
                                   ('seqMIDIPriority', 0xD740, 0x100)]:
            self.assertEqual(obj.symbols[name][:3], ('.bss', offset, size))


class SequenceRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('clang')
        if not compiler:
            raise unittest.SkipTest('clang is required for the source-body harness')
        source = (ROOT / 'src/musyx/runtime/seq.c').read_text()
        header = (ROOT / 'src/musyx/runtime/synth_internal.h').read_text()
        queue = (ROOT / 'include/musyx/synth_queue.h').read_text()
        constants = '\n'.join(line for line in queue.splitlines()
                              if re.match(r'#define SYNTH_(MAX_VOICES|VOICE_NOTE_COUNT)\s', line))
        constants += '\n' + '\n'.join(line for line in source.splitlines()
                                        if line.startswith('#define SYNTH_'))
        records = header[header.index('#define SYNTH_CALLBACK_COUNT'):header.index('extern SynthCallbackLink seqNote')]
        records = re.sub(r'^STATIC_ASSERT[^\n]*\n', '', records, flags=re.M)
        records = queue[queue.index('typedef struct SynthPage'):queue.index('u32 seqStartPlay')] + records
        bodies = '\n'.join(function(source, name) for name in (
            'ClearNotes', 'ResetNotes', 'KillNotes', 'seqStop', 'seqSpeed', 'seqMute', 'seqVolume', 'seqInit',
            'resolveHandle', 'seqCrossFade', 'HandleTrackEvents'))
        resolver = function(header, 'seqGetPrivateIdInline')
        cls.temporary = tempfile.TemporaryDirectory(prefix='sfa-sequencer-')
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        fixture = directory / 'seq.c'
        fixture.write_text(PREFIX + constants + '\n' + records + MOCKS + resolver + '\n' + bodies + CHECKS)
        cls.modules = []
        for optimization in ('-O0', '-O2'):
            library = directory / (optimization[1:] + ('.dll' if sys.platform == 'win32' else '.so'))
            command = [compiler, '-shared', optimization, '-fno-builtin', str(fixture), '-o', str(library)]
            command += ['-fuse-ld=lld', '-nostdlib', '-Wl,/noentry'] if sys.platform == 'win32' else ['-fPIC']
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            module = ctypes.CDLL(str(library))
            if sys.platform == 'win32':
                kernel = ctypes.WinDLL('kernel32', use_last_error=True)
                kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
                cls.addClassCleanup(kernel.FreeLibrary, module._handle)
            cls.modules.append((optimization, module))

    def check(self, name, cases):
        for optimization, module in self.modules:
            run = getattr(module, name)
            run.argtypes = [ctypes.c_int] * len(cases[0])
            run.restype = ctypes.c_int
            for case in cases:
                with self.subTest(optimization=optimization, case=case):
                    self.assertEqual(run(*case), 0)

    def test_initialization_preserves_other_fields(self):
        self.check('checkInit', [()])

    def test_stop_lists_and_note_recycling(self):
        self.check('checkStop', [(slot, state, mode) for slot in range(3)
                                for state in (1, 2) for mode in range(3)])

    def test_speed_and_mute(self):
        self.check('checkControls', [(slot, pending) for slot in range(8) for pending in (0, 1)])

    def test_volume_groups_and_pending_modes(self):
        self.check('checkVolume', [(pending, mode) for pending in (0, 1)
                                  for mode in (0, 1, 2, 3, 4, 0x12)])

    def test_pending_crossfade(self):
        self.check('checkCrossFade', [(slot, irq, flags) for slot in range(8) for irq in (0, 1)
                                     for flags in (4, 0xFF)])

    def test_section_loop_restart(self):
        self.check('checkTrackLoop', [(section, time_index, master) for section in range(16)
                                    for time_index in (0, 1) for master in (0, 1)])


PREFIX = r'''
#include <stddef.h>
typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef short s16;
typedef unsigned int u32;
typedef int s32;
typedef float f32;
typedef struct SynthPage SynthPage;
typedef struct McmdVoiceState McmdVoiceState;
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif
'''

MOCKS = r'''
static SynthCallbackLink seqNote[SYNTH_CALLBACK_COUNT];
static SynthVoice seqInstance[SYNTH_MAX_VOICES];
static u16 seqMIDIPriority[SYNTH_MAX_VOICES][SYNTH_VOICE_NOTE_COUNT];
static SynthVoice *seqActiveRoot, *seqPausedRoot, *seqFreeRoot;
static SynthCallbackLink* noteFree;
static u32 seq_next_id, pendingId;
static u32 killed[256];
static int killedCount, volumeCount;
typedef struct { u32 volume, time, group, mode, handle; } VolumeCall;
static VolumeCall volumeCalls[65];
static SynthVoice expectedVoices[SYNTH_MAX_VOICES];
static SynthCallbackLink expectedNotes[SYNTH_CALLBACK_COUNT];
static void voiceKillSound(u32 id) { killed[killedCount++] = id; }
static void synthVolume(u8 volume, u16 time, u8 group, u8 mode, u32 handle) {
    VolumeCall* call = &volumeCalls[volumeCount++];
    call->volume = volume; call->time = time; call->group = group;
    call->mode = mode; call->handle = handle;
}
static void fill(void* ptr, u8 value, size_t size) {
    size_t i; for (i = 0; i < size; i++) ((u8*)ptr)[i] = value;
}
static void copy(void* out, const void* in, size_t size) {
    size_t i; for (i = 0; i < size; i++) ((u8*)out)[i] = ((const u8*)in)[i];
}
void* memcpy(void* out, const void* in, size_t size) { copy(out, in, size); return out; }
static int equal(const void* a, const void* b, size_t size) {
    size_t i; for (i = 0; i < size; i++) if (((const u8*)a)[i] != ((const u8*)b)[i]) return 0;
    return 1;
}
static int unexpectedCalls;
static void sndSeqVolume(u8 v, u16 t, u32 id, u8 mode) { unexpectedCalls++; }
static void seqContinue(u32 id) { unexpectedCalls++; }
static void sndSeqContinue(u32 id) { unexpectedCalls++; }
static void sndSeqMute(u32 id, u32 a, u32 b) { unexpectedCalls++; }
static void sndSeqSpeed(u32 id, u16 speed) { unexpectedCalls++; }
static u32 seqGetPrivateId(u32 id) { unexpectedCalls++; return 0; }
static u32 seqPlaySong(u16 g, u16 s, void* a, SynthPlayParams* p, u8 irq, u8 studio) {
    unexpectedCalls++; return 0;
}
static u32 sndSeqPlayEx(u16 g, u16 s, void* a, SynthPlayParams* p, u8 studio) {
    unexpectedCalls++; return 0;
}
static SynthVoice* cseq;
static SynthSequenceEvent loopEvent;
static int loopStage, loopError, masterCalls, deltaCalls, restartCalls;
static u8 expectedSection;
static void HandleMasterTrack(u8 section) {
    if (section != expectedSection || loopStage != 1 ||
        cseq->section[section].masterTrackCursor != cseq->section[section].masterTrackBase) loopError++;
    masterCalls++;
}
static void SetTickDelta(SynthSequenceQueue* section, u32 delta) {
    if (section != &cseq->section[expectedSection] || delta != 123 || masterCalls != 1) loopError++;
    deltaCalls++;
}
static void InitTrackEventsSection(u8 section) {
    if (section != expectedSection || loopStage != 1) loopError++;
    restartCalls++; loopStage = 2;
    loopEvent.time = 0xFFFFFFFFu; cseq->section[section].eventList = &loopEvent;
}
static SynthSequenceEvent* HandleEvent(SynthSequenceEvent* event, u8 section, u32* flag) {
    if (event != &loopEvent || section != expectedSection || loopStage != 0) loopError++;
    loopStage = 1; *flag = 1; return NULL;
}
static void InsertGlobalEvent(SynthSequenceQueue* section, SynthSequenceEvent* event) { loopError++; }
'''

CHECKS = r'''
EXPORT int checkInit(void) {
    int i;
    fill(seqNote, 0xA5, sizeof(seqNote)); fill(seqInstance, 0xA5, sizeof(seqInstance));
    fill(seqMIDIPriority, 0xA5, sizeof(seqMIDIPriority));
    copy(expectedNotes, seqNote, sizeof(seqNote)); copy(expectedVoices, seqInstance, sizeof(seqInstance));
    seq_next_id = 123; seqActiveRoot = &seqInstance[1]; seqPausedRoot = &seqInstance[2];
    for (i = 0; i < 8; i++) {
        expectedVoices[i].prev = i ? &seqInstance[i - 1] : NULL;
        expectedVoices[i].next = i != 7 ? &seqInstance[i + 1] : NULL;
        expectedVoices[i].slotIndex = i; expectedVoices[i].state = 0;
    }
    for (i = 0; i < 256; i++) {
        expectedNotes[i].prev = i ? &seqNote[i - 1] : NULL;
        expectedNotes[i].next = i != 255 ? &seqNote[i + 1] : NULL;
    }
    seqInit();
    if (seqActiveRoot || seqPausedRoot || seqFreeRoot != seqInstance || noteFree != seqNote || seq_next_id) return 1;
    if (!equal(seqInstance, expectedVoices, sizeof(seqInstance))) return 2;
    if (!equal(seqNote, expectedNotes, sizeof(seqNote))) return 3;
    for (i = 0; i < sizeof(seqMIDIPriority); i++) if (((u8*)seqMIDIPriority)[i] != 255) return 4;
    return 0;
}

static void prepare(void) {
    fill(seqInstance, 0, sizeof(seqInstance)); fill(seqNote, 0, sizeof(seqNote));
    seqInit(); killedCount = 0; volumeCount = 0;
}

EXPORT int checkStop(int slot, int state, int mode) {
    SynthVoice* voice;
    SynthVoice *root, *expectedRoot, *expectedFree;
    SynthCallbackLink* note;
    int i, index, order[5] = {3, 4, 2, 0, 1};
    prepare();
    for (i = 0; i < 3; i++) {
        seqInstance[i].state = state; seqInstance[i].handle = 0x100 + i;
        seqInstance[i].next = i < 2 ? &seqInstance[i + 1] : NULL;
    }
    seqFreeRoot = &seqInstance[3]; seqFreeRoot->prev = NULL;
    if (state == 1) seqActiveRoot = seqInstance; else seqPausedRoot = seqInstance;
    root = seqInstance; voice = &seqInstance[slot]; voice->syncSeqIdPtr = &pendingId;
    voice->callbackLists[0] = &seqNote[0]; voice->callbackLists[1] = &seqNote[2];
    voice->callbackLists[2] = &seqNote[3];
    seqNote[0].prev = NULL; seqNote[1].next = NULL;
    seqNote[2].prev = seqNote[2].next = NULL;
    seqNote[3].prev = NULL; seqNote[4].next = NULL;
    noteFree = &seqNote[5]; noteFree->prev = NULL;
    for (i = 0; i < 5; i++) seqNote[i].callbackId = 100 + i;
    copy(expectedVoices, seqInstance, sizeof(seqInstance)); copy(expectedNotes, seqNote, sizeof(seqNote));
    expectedRoot = root; expectedFree = seqFreeRoot;
    if (mode == 0) {
        if (slot) expectedVoices[slot - 1].next = voice->next; else expectedRoot = voice->next;
        if (slot != 2) expectedVoices[slot + 1].prev = voice->prev;
        expectedVoices[3].prev = voice;
        expectedVoices[slot].prev = NULL; expectedVoices[slot].next = seqFreeRoot;
        expectedVoices[slot].state = 0; expectedFree = voice;
        if (state == 1) for (i = 0; i < 3; i++) expectedVoices[slot].callbackLists[i] = NULL;
    } else if (mode == 1) {
        expectedVoices[slot].syncSeqIdPtr = NULL;
    }
    seqStop(mode == 2 ? 0x12345678 : (0x100 + slot) | (mode ? 0x80000000u : 0));
    if (!equal(seqInstance, expectedVoices, sizeof(seqInstance))) return 1;
    if ((state == 1 ? seqActiveRoot : seqPausedRoot) != expectedRoot || seqFreeRoot != expectedFree) return 2;
    if (mode == 0 && state == 1) {
        if (killedCount != 5) return 3;
        for (i = 0; i < 5; i++) if (killed[i] != 100 + i) return 4;
        note = noteFree;
        for (i = 0; i < 256; i++) {
            index = i < 5 ? order[i] : i;
            if (note != &seqNote[index]) return 5;
            if (note->prev != (i ? &seqNote[i <= 5 ? order[i - 1] : i - 1] : NULL)) return 6;
            note = note->next;
        }
        if (note) return 7;
    } else if (killedCount || noteFree != &seqNote[5] || !equal(seqNote, expectedNotes, sizeof(seqNote))) return 8;
    return 0;
}

static SynthVoice* prepareControl(int slot) {
    SynthVoice* voice;
    prepare(); voice = &seqInstance[slot];
    seqActiveRoot = voice; voice->next = voice->prev = NULL;
    voice->handle = 0x123; voice->state = 1; voice->syncSeqIdPtr = &pendingId;
    voice->syncCrossInfo.flags = 0x40;
    return voice;
}

EXPORT int checkControls(int slot, int pending) {
    int i;
    SynthVoice* voice = prepareControl(slot);
    copy(expectedVoices, seqInstance, sizeof(seqInstance));
    if (pending) {
        expectedVoices[slot].syncCrossInfo.flags |= SND_CROSSFADE_SPEED | SND_CROSSFADE_TRACKMUTE;
        expectedVoices[slot].syncCrossInfo.speed2 = 0x3456;
        expectedVoices[slot].syncCrossInfo.trackMute2[0] = 0x01234567;
        expectedVoices[slot].syncCrossInfo.trackMute2[1] = 0x89ABCDEF;
    } else {
        for (i = 0; i < 16; i++) expectedVoices[slot].section[i].speed = 0x3456;
        expectedVoices[slot].trackMute[0] = 0x01234567; expectedVoices[slot].trackMute[1] = 0x89ABCDEF;
    }
    seqSpeed(0x123 | (pending ? 0x80000000u : 0), 0x3456);
    seqMute(0x123 | (pending ? 0x80000000u : 0), 0x01234567, 0x89ABCDEF);
    return !equal(seqInstance, expectedVoices, sizeof(seqInstance));
}

EXPORT int checkVolume(int pending, int mode) {
    int i, count;
    SynthVoice* voice = prepareControl(3);
    voice->defaultVolumeGroup = 23;
    for (i = 0; i < 64; i++) voice->trackVolumeGroup[i] = 23 + i % 4;
    copy(expectedVoices, seqInstance, sizeof(seqInstance));
    if (pending) {
        switch (mode & 15) {
        case 0: expectedVoices[3].syncCrossInfo.vol2 = 17; break;
        case 1: expectedVoices[3].syncSeqIdPtr = NULL; break;
        case 2: expectedVoices[3].syncCrossInfo.flags |= SND_CROSSFADE_PAUSENEW;
                expectedVoices[3].syncCrossInfo.vol2 = 17; break;
        case 3: expectedVoices[3].syncCrossInfo.flags |= SND_CROSSFADE_MUTENEW;
                expectedVoices[3].syncCrossInfo.vol2 = 17; break;
        }
    }
    seqVolume(17, 123, 0x123 | (pending ? 0x80000000u : 0), mode);
    if (!equal(seqInstance, expectedVoices, sizeof(seqInstance))) return 1;
    if (pending) return volumeCount != 0;
    if (volumeCount != 49) return 2;
    if (volumeCalls[0].group != 23 || volumeCalls[0].mode != mode || volumeCalls[0].handle != 0x123) return 3;
    count = 1;
    for (i = 0; i < 64; i++) if (i % 4) {
        if (volumeCalls[count].group != 23 + i % 4 || volumeCalls[count].mode ||
            volumeCalls[count].handle != 0xFFFFFFFFu) return 4;
        count++;
    }
    for (i = 0; i < volumeCount; i++) if (volumeCalls[i].volume != 17 || volumeCalls[i].time != 123) return 5;
    return 0;
}

EXPORT int checkCrossFade(int slot, int irq, int flags) {
    SynthVoice* voice = prepareControl(slot);
    SynthStartRequest request;
    u32 output = 0xDEADBEEF;
    fill(&request, 0x5A, sizeof(request));
    request.seqId1 = voice->handle; request.flags = flags;
    copy(expectedVoices, seqInstance, sizeof(seqInstance));
    copy(&expectedVoices[slot].syncCrossInfo, &request, sizeof(request));
    expectedVoices[slot].syncCrossInfo.flags &= ~SND_CROSSFADE_SYNC;
    expectedVoices[slot].syncActive = 1; expectedVoices[slot].syncSeqIdPtr = &output;
    unexpectedCalls = 0;
    seqCrossFade(&request, &output, irq);
    if (!equal(seqInstance, expectedVoices, sizeof(seqInstance))) return 1;
    if (output != (voice->handle | SYNTH_HANDLE_QUEUED_FLAG)) return 2;
    if (request.flags != flags || unexpectedCalls || volumeCount) return 3;
    return 0;
}

EXPORT int checkTrackLoop(int section, int timeIndex, int master) {
    SynthArrangement arrangement;
    SynthSequenceQueue* queue;
    u8 masterData[8];
    prepare(); cseq = &seqInstance[3]; queue = &cseq->section[section];
    fill(&arrangement, 0, sizeof(arrangement)); arrangement.loopPoint[section] = 57;
    cseq->arrbase = (u8*)&arrangement;
    queue->timeIndex = timeIndex; queue->time[timeIndex].high = 99;
    queue->time[timeIndex].low = 0x12345678; queue->time[timeIndex ^ 1].low = 0x87654321;
    queue->loopCount = 19;
    queue->masterTrackBase = master ? masterData : NULL;
    queue->masterTrackCursor = &masterData[4];
    fill(&loopEvent, 0, sizeof(loopEvent)); queue->eventList = &loopEvent;
    copy(expectedVoices, seqInstance, sizeof(seqInstance));
    expectedVoices[3].section[section].timeIndex ^= 1;
    expectedVoices[3].section[section].time[timeIndex ^ 1].high = 57;
    expectedVoices[3].section[section].time[timeIndex ^ 1].low = 0x12345678;
    expectedVoices[3].section[section].loopCount = 20;
    if (master) expectedVoices[3].section[section].masterTrackCursor = masterData;
    expectedSection = section; loopStage = loopError = masterCalls = deltaCalls = restartCalls = 0;
    if (HandleTrackEvents(section, 123) != 1) return 1;
    if (!equal(seqInstance, expectedVoices, sizeof(seqInstance))) return 2;
    if (loopError || loopStage != 2 || masterCalls != master || deltaCalls != master || restartCalls != 1) return 3;
    return 0;
}
'''


if __name__ == '__main__':
    unittest.main()
