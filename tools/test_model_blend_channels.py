"""Exercise production morph-channel state and buffer selection with a blend-call recorder."""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]


class ModelBlendChannelTests(unittest.TestCase):
    def test_refresh_and_channel_composition(self):
        compiler = shutil.which('clang')
        if compiler is None:
            self.skipTest('clang is required for source-body tests')
        source = (ROOT / 'src/main/model.c').read_text()
        header = (ROOT / 'include/main/model.h').read_text()
        channel = re.search(r'typedef struct ObjModelBlendChannel \{.*?\} ObjModelBlendChannel;',
                            header, re.S).group()
        flags = '\n'.join(re.findall(r'^#define BLENDCHAN_.*$', header, re.M))
        work = re.search(r'typedef struct ModelBlendChannelFlags \{.*?\} ModelBlendChannelFlags;',
                         source, re.S).group()
        initializers = '\n'.join(re.findall(r'^const ModelBlendChannelFlags .*$', source, re.M))
        functions = []
        for name in ('ObjModel_ApplyBlendChannels', 'ObjModel_AdvanceBlendChannels',
                     'ObjModel_NeedsBlendChannelUpdate', 'ObjModel_SetBlendChannelWeight',
                     'ObjModel_SetBlendChannelTargets', 'ObjModel_ClearBlendChannels',
                     'ObjModel_ToggleVertexBuffer'):
            start, end = find_function_body(source, name)
            declaration = source.rfind('\n', 0, source.rfind(name, 0, start)) + 1
            functions.append(source[declaration:end + 1])
        fixture = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef short s16;
typedef float f32;
''' + channel + '\n' + flags + '\n' + work + '\n' + initializers + r'''
typedef struct ModelFileHeader {
    u16** morphTargetPtrs;
    u16 vertexCount;
    u8 morphTargetCount;
    void* vertexAnimEntries;
    u8* vertices;
} ModelFileHeader;
typedef struct ObjModel {
    ModelFileHeader* file;
    ObjModelBlendChannel* blendChannels;
    u8* vtxBuf[2];
    u16 bufferFlags;
    u8 vtxBufDirty;
} ObjModel;
typedef struct BlendCall { u8 *src, *dst; int weight; u16 a, b; } BlendCall;
static BlendCall calls[3];
static int callCount;
static void modelBlendMorphTargets(u8* src, u8* dst, u16 count, u16* a, u16* b, int weight) {
    assert(count == 1 && callCount < 3);
    calls[callCount++] = (BlendCall){src, dst, weight, *a, *b};
}
''' + '\n'.join(functions) + r'''
static ObjModelBlendChannel channels[3];
static u8 base[6], output0[6], output1[6];
static u16 target0 = 100, target1 = 101;
static u16* targets[] = {&target0, &target1};
static ModelFileHeader file;
static ObjModel model;
static int frames;
static void reset(void) {
    int i;
    memset(channels, 0, sizeof(channels));
    for (i = 0; i < 3; i++) channels[i].morphTargetA = channels[i].morphTargetB = -1;
    file = (ModelFileHeader){targets, 1, 2, NULL, base};
    model = (ObjModel){&file, channels, {output0, output1}, 0, 0};
    callCount = 0;
}
static void apply(void) {
    callCount = 0;
    model.vtxBufDirty = 0;
    ObjModel_ToggleVertexBuffer(&model);
    ObjModel_ApplyBlendChannels(&model);
    frames++;
}
int main(void) {
    ObjModelBlendChannel saved;
    reset();
    ObjModel_SetBlendChannelTargets(&model, 0, -1, 0, .25f, BLENDCHAN_FLAG_MANUAL);
    ObjModel_SetBlendChannelWeight(&model, 0, .5f);
    assert(channels[0].previousWeight == -1 && ObjModel_NeedsBlendChannelUpdate(&model));
    apply();
    assert(callCount == 1 && calls[0].src == base && calls[0].dst == output1);
    assert(calls[0].weight == 32768 && calls[0].a == 2 && calls[0].b == target0);
    assert(channels[0].previousWeight == .5f && channels[0].flags == (BLENDCHAN_FLAG_MANUAL | BLENDCHAN_FLAG_REFRESH_NEXT));
    assert(model.vtxBufDirty && ObjModel_NeedsBlendChannelUpdate(&model));
    apply();
    assert(callCount == 1 && calls[0].dst == output0 && calls[0].weight == 32768);
    assert(channels[0].flags == BLENDCHAN_FLAG_MANUAL && !ObjModel_NeedsBlendChannelUpdate(&model));
    apply();
    assert(callCount == 0 && !model.vtxBufDirty); /* targets still selected, no update pending */
    ObjModel_SetBlendChannelWeight(&model, 0, .5f); /* even an unchanged value requests two refreshes */
    apply();
    assert(callCount == 1 && channels[0].flags & BLENDCHAN_FLAG_REFRESH_NEXT);
    ObjModel_SetBlendChannelWeight(&model, 0, .25f); /* restart the two-pass refresh */
    apply();
    assert(callCount == 1 && channels[0].flags & BLENDCHAN_FLAG_REFRESH_NEXT);
    apply();
    assert(callCount == 1 && !ObjModel_NeedsBlendChannelUpdate(&model));

    ObjModel_AdvanceBlendChannels(&model, 10);
    assert(channels[0].weight == .25f); /* manual weights do not integrate */
    ObjModel_SetBlendChannelTargets(&model, 0, -1, 1, -.125f, BLENDCHAN_FLAG_KEEP_WEIGHT);
    assert(channels[0].weight == .25f && channels[0].weightRate == -.125f);
    saved = channels[0];
    ObjModel_SetBlendChannelTargets(&model, 0, -1, 1, 9, 0);
    assert(memcmp(&saved, &channels[0], sizeof(saved)) == 0); /* identical targets ignore new settings */
    ObjModel_AdvanceBlendChannels(&model, 1);
    assert(channels[0].weight == .125f && channels[0].previousWeight == -1);
    ObjModel_AdvanceBlendChannels(&model, 10);
    assert(channels[0].weight == .002f && channels[0].weightRate == .001f);
    channels[0].weight = .9f; channels[0].weightRate = .2f;
    ObjModel_AdvanceBlendChannels(&model, 1);
    assert(channels[0].weight == .99f && channels[0].weightRate == .001f);

    reset();
    ObjModel_SetBlendChannelTargets(&model, 1, -1, 0, 0, BLENDCHAN_FLAG_MANUAL | BLENDCHAN_FLAG_ALLOW_NEGATIVE);
    ObjModel_SetBlendChannelWeight(&model, 1, -2);
    apply();
    assert(callCount == 1 && channels[1].weight == -1 && calls[0].weight == -65536);
    channels[1].flags &= ~BLENDCHAN_FLAG_ALLOW_NEGATIVE;
    ObjModel_SetBlendChannelWeight(&model, 1, -.5f);
    apply();
    assert(callCount == 1 && channels[1].weight == 0 && calls[0].weight == 0);

    reset();
    ObjModel_SetBlendChannelTargets(&model, 0, -1, 0, 0, BLENDCHAN_FLAG_MANUAL);
    ObjModel_SetBlendChannelTargets(&model, 1, -1, 1, 0, BLENDCHAN_FLAG_MANUAL);
    ObjModel_SetBlendChannelTargets(&model, 2, 0, 1, 0, BLENDCHAN_FLAG_MANUAL);
    apply();
    assert(callCount == 2 && calls[0].b == target1 && calls[0].src == base);
    assert(calls[1].a == target0 && calls[1].src == output1 && calls[1].dst == output1);
    apply();
    assert(callCount == 2 && calls[1].src == output0);
    apply();
    assert(callCount == 0);
    ObjModel_SetBlendChannelWeight(&model, 2, .5f);
    apply();
    assert(callCount == 2); /* additive change rebuilds the active base channel */
    apply();
    assert(callCount == 2);
    ObjModel_SetBlendChannelWeight(&model, 1, .5f);
    apply();
    assert(callCount == 2); /* base change reapplies the additive channel */
    apply();
    assert(callCount == 2);
    apply();
    assert(callCount == 0);
    file.vertexAnimEntries = &file;
    apply();
    assert(callCount == 2); /* vertex animation requires refresh even with steady weights */
    file.vertexAnimEntries = NULL;
    ObjModel_ClearBlendChannels(&model);
    apply();
    assert(callCount == 2 && calls[0].a == 2 && calls[0].b == 2 && calls[0].weight == 0);
    apply();
    assert(callCount == 2 && !ObjModel_NeedsBlendChannelUpdate(&model));
    apply();
    assert(callCount == 0);

    reset();
    ObjModel_SetBlendChannelTargets(&model, 2, -1, 0, 0, BLENDCHAN_FLAG_MANUAL);
    apply();
    assert(callCount == 1 && calls[0].src == base); /* additive-only starts from file vertices */
    saved = channels[2];
    ObjModel_SetBlendChannelTargets(&model, 2, -2, 0, 0, 0);
    ObjModel_SetBlendChannelTargets(&model, 2, -1, 2, 0, 0);
    ObjModel_SetBlendChannelTargets(&model, 3, -1, 0, 0, 0);
    assert(memcmp(&saved, &channels[2], sizeof(saved)) == 0);
    file.morphTargetPtrs = NULL;
    ObjModel_AdvanceBlendChannels(&model, 10);
    ObjModel_SetBlendChannelWeight(&model, 2, 5);
    ObjModel_ClearBlendChannels(&model);
    apply();
    assert(callCount == 0 && !ObjModel_NeedsBlendChannelUpdate(&model));
    assert(memcmp(&saved, &channels[2], sizeof(saved)) == 0);
    printf("%d blend-channel apply passes checked\n", frames);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'channels.c'
            path.write_text(fixture)
            for optimization in ('-O0', '-O2'):
                executable = Path(directory) / ('channels' + optimization)
                subprocess.run([compiler, '-std=c99', optimization, str(path), '-o', str(executable)],
                               check=True, capture_output=True, text=True, timeout=30)
                result = subprocess.run([str(executable)], check=True, capture_output=True, text=True, timeout=30)
                print(optimization, result.stdout.strip())


if __name__ == '__main__':
    unittest.main()
