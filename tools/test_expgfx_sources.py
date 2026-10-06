#!/usr/bin/env python3
"""Run effect source-table allocation and cleanup with native production records.

Textures and cache flushing are spies. Slot fixtures encode the retail table
index explicitly; this does not test host bitfield serialization, particle
simulation, or GPU rendering.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

from test_map_page_loading import PRELUDE
from test_map_block_init import TYPES
from test_render_queue import record
from test_model_instance_layout import function

ROOT = Path(__file__).resolve().parents[1]
SERVICES = r'''
static ExpgfxSlot pools[80][25];
static GameObject objects[81];
static unsigned char textures[81];
static int textureFrees[81],flushes,warnings,cases;
static void* lastFlush;
static int lastFlushSize;
static void textureFree(Texture* texture) {
    assert(gExpgfxTextureFreeInProgress==1);
    ptrdiff_t index=(unsigned char*)texture-textures;
    assert(index>=0 && index<=80 && (uintptr_t)texture>UINT32_MAX); textureFrees[index]++;
}
static void DCFlushRange(void* pointer,int size) { lastFlush=pointer; lastFlushSize=size; flushes++; }
static void debugPrintf(const char* message) { assert(strncmp(message,"expgfx.c:",9)==0); warnings++; }
static void reset(void) {
    memset(pools,0,sizeof(pools)); memset(gExpgfxTableEntries,0,sizeof(gExpgfxTableEntries));
    memset(gExpgfxResourceEntries,0,sizeof(gExpgfxResourceEntries));
    memset(gExpgfxSlotActiveMasks,0,sizeof(gExpgfxSlotActiveMasks));
    memset(gExpgfxPoolActiveCounts,0,sizeof(gExpgfxPoolActiveCounts));
    memset(gExpgfxTrackedPoolSourceIds,0,sizeof(gExpgfxTrackedPoolSourceIds));
    memset(gExpgfxStaticPoolSlotTypeIds,0xff,sizeof(gExpgfxStaticPoolSlotTypeIds));
    memset(gExpgfxStaticPoolFrameFlags,0,sizeof(gExpgfxStaticPoolFrameFlags));
    memset(gExpgfxPoolSourceModes,0,sizeof(gExpgfxPoolSourceModes));
    memset(textureFrees,0,sizeof(textureFrees)); warnings=flushes=0;
    gExpgfxTextureFreeInProgress=0;
    for (int i=0;i<80;i++) gExpgfxSlotPoolBases[i]=pools[i];
}
'''
CHECKS = r'''
static void checkTable(void) {
    reset();
    for (int i=0;i<80;i++) {
        int result=expgfx_addToTable(textures+i,&objects[i].anim,&objects[80-i],100+i);
        assert(result==i && gExpgfxTableEntries[i].resource==textures+i);
        assert(gExpgfxTableEntries[i].sourceObject==&objects[i].anim && gExpgfxTableEntries[i].sourceParent==&objects[80-i]);
        assert(gExpgfxTableEntries[i].refCount==1 && gExpgfxTableEntries[i].resourceId==100+i);
    }
    for (int i=0;i<80;i++) {
        assert(expgfx_addToTable(textures+i,&objects[i].anim,&objects[80-i],-7)==i);
        assert(gExpgfxTableEntries[i].refCount==2 && gExpgfxTableEntries[i].resourceId==100+i);
        gExpgfxTableEntries[i].refCount=65535;
        assert(expgfx_addToTable(textures+i,&objects[i].anim,&objects[80-i],0)==-1);
        assert(gExpgfxTableEntries[i].refCount==65535); gExpgfxTableEntries[i].refCount=2;
    }
    ExpgfxTableEntry saved[80]; memcpy(saved,gExpgfxTableEntries,sizeof(saved));
    assert(expgfx_addToTable(textures+80,&objects[0].anim,&objects[80],0)==-1);
    assert(expgfx_addToTable(textures,&objects[80].anim,&objects[80],0)==-1);
    assert(expgfx_addToTable(textures,&objects[0].anim,&objects[0],0)==-1);
    assert(memcmp(saved,gExpgfxTableEntries,sizeof(saved))==0 && warnings==83);
    gExpgfxTableEntries[37].refCount=0;
    assert(expgfx_addToTable(NULL,NULL,NULL,-8)==37);
    assert(!gExpgfxTableEntries[37].resource && !gExpgfxTableEntries[37].sourceObject);
    assert(!gExpgfxTableEntries[37].sourceParent && gExpgfxTableEntries[37].resourceId==-8);
    cases++;
}
static void checkSlotSelection(int pool,int slot) {
    reset();
    for (int i=0;i<80;i++) {
        gExpgfxPoolActiveCounts[i]=25; gExpgfxSlotActiveMasks[i]=(1u<<25)-1;
        gExpgfxStaticPoolSlotTypeIds[i]=12; gExpgfxTrackedPoolSourceIds[i]=&objects[0].anim;
    }
    gExpgfxPoolActiveCounts[pool]=24; gExpgfxSlotActiveMasks[pool]^=1u<<slot;
    gExpgfxTrackedPoolSourceIds[pool]=&objects[79].anim;
    short outPool=-123,outSlot=-123;
    assert(expgfxGetSlot(&outPool,&outSlot,12,-1,&objects[79])==1);
    assert(outPool==pool && outSlot==slot && gExpgfxPoolActiveCounts[pool]==25);
    assert(gExpgfxSlotActiveMasks[pool]==(1u<<25)-1);
    outPool=outSlot=-123; assert(expgfxGetSlot(&outPool,&outSlot,12,-1,&objects[79])==-1);
    assert(outPool==-123 && outSlot==-123);
    gExpgfxPoolActiveCounts[pool]=0; gExpgfxSlotActiveMasks[pool]=0;
    assert(expgfxGetSlot(&outPool,&outSlot,13,-1,&objects[80])==(pool==79 ? -1 : 1));
    if (pool!=79) {
        assert(outPool==pool && outSlot==0 && gExpgfxStaticPoolSlotTypeIds[pool]==13);
        assert(gExpgfxTrackedPoolSourceIds[pool]==&objects[79].anim);
    } else {
        assert(outPool==-123 && outSlot==-123);
        assert(expgfxGetSlot(&outPool,&outSlot,13,79,&objects[80])==1);
        assert(outPool==79 && outSlot==0);
    }
    cases++;
}
static void checkRemove(int table,int skip,int flush,int refs,int resource) {
    reset(); int pool=79-table,slot=table%25;
    ExpgfxSlot* effect=&pools[pool][slot];
    effect->encodedTableIndex=table*2+1; effect->sequenceId=123; effect->behaviorFlags=~0u;
    gExpgfxSlotActiveMasks[pool]=1u<<slot; gExpgfxPoolActiveCounts[pool]=1;
    gExpgfxStaticPoolSlotTypeIds[pool]=12;
    ExpgfxTableEntry* entry=&gExpgfxTableEntries[table];
    *entry=(ExpgfxTableEntry){&objects[table].anim,&objects[80],resource ? textures+table : NULL,refs,23};
    ExpgfxTableEntry expected=*entry;
    if (!skip && refs) {
        expected.refCount--;
        if (!expected.refCount) { expected.resource=NULL; expected.sourceObject=NULL; }
    }
    expgfxRemove(pools[pool],pool,slot,skip,flush);
    assert(memcmp(entry,&expected,sizeof(expected))==0);
    assert(textureFrees[table]==(!skip && resource) && warnings==(!skip && !refs));
    assert(!effect->behaviorFlags && effect->sequenceId==-1 && effect->encodedTableIndex==table*2+1);
    assert(!gExpgfxSlotActiveMasks[pool] && !gExpgfxPoolActiveCounts[pool] && gExpgfxStaticPoolSlotTypeIds[pool]==-1);
    assert(flushes==flush && (!flush || (lastFlush==effect && lastFlushSize==160)));
    expgfxRemove(pools[pool],pool,slot,skip,flush);
    assert(memcmp(entry,&expected,sizeof(expected))==0 && flushes==flush);
    cases++;
}
static void populate(void) {
    reset();
    for (int i=0;i<80;i++) {
        gExpgfxTrackedPoolSourceIds[i]=&objects[i%3].anim;
        gExpgfxPoolActiveCounts[i]=1; gExpgfxSlotActiveMasks[i]=1u<<(i%25);
        gExpgfxStaticPoolSlotTypeIds[i]=17; gExpgfxStaticPoolFrameFlags[i]=3; gExpgfxPoolSourceModes[i]=2;
        gExpgfxTableEntries[i]=(ExpgfxTableEntry){&objects[i%2].anim,&objects[80],textures+i,1,i};
        pools[i][i%25].encodedTableIndex=i*2; pools[i][i%25].sequenceId=100+i;
    }
}
static void checkFree(int owner,int wrapper) {
    populate(); void* source=owner<0 ? NULL : &objects[owner];
    if (wrapper==0) expgfx_free(source);
    else if (wrapper==1) expgfx_free2(source);
    else expgfx_ownerFree3(source);
    for (int i=0;i<80;i++) {
        int visited=owner>=0 && i%3==owner,removed=visited && i%2==owner;
        assert(gExpgfxPoolActiveCounts[i]==!removed && textureFrees[i]==removed);
        assert(gExpgfxSlotActiveMasks[i]==(removed ? 0u : 1u<<(i%25)));
        assert(gExpgfxTableEntries[i].sourceObject==(removed ? NULL : &objects[i%2].anim));
        assert(gExpgfxTableEntries[i].sourceParent==&objects[80]);
        assert(gExpgfxTrackedPoolSourceIds[i]==(visited ? NULL : &objects[i%3].anim));
        assert(gExpgfxStaticPoolFrameFlags[i]==(visited ? 0 : 3));
        assert(gExpgfxStaticPoolSlotTypeIds[i]==(removed ? -1 : 17));
    }
    cases++;
}
static void checkReset(int mode) {
    populate(); gExpgfxTrackedSourceFrameMasks[0]=gExpgfxTrackedSourceFrameMasks[1]=~(u64)0;
    for (int i=0;i<32;i++) gExpgfxResourceEntries[i]=(ExpgfxResourceEntry){textures+i,5,i+1,9};
    if (!mode) expgfxRemoveAll();
    else if (mode==1) expgfx_resetAllPools();
    else expgfx_onMapSetup();
    for (int i=0;i<80;i++) {
        assert(!gExpgfxSlotActiveMasks[i] && !gExpgfxPoolActiveCounts[i] && gExpgfxStaticPoolSlotTypeIds[i]==-1);
        assert(!gExpgfxTableEntries[i].refCount && !gExpgfxTableEntries[i].sourceObject && !gExpgfxTableEntries[i].resource);
        assert(gExpgfxTableEntries[i].sourceParent==&objects[80]);
        assert(gExpgfxTrackedPoolSourceIds[i]==(mode ? NULL : &objects[i%3].anim));
        assert(gExpgfxStaticPoolFrameFlags[i]==(mode ? 0 : 3));
        assert(gExpgfxPoolSourceModes[i]==(mode==2 ? 0 : 2));
        assert(textureFrees[i]==1+(mode && i<32));
    }
    for (int i=0;i<32;i++) {
        ExpgfxResourceEntry expected=mode ? (ExpgfxResourceEntry){0} : (ExpgfxResourceEntry){textures+i,5,i+1,9};
        assert(memcmp(&gExpgfxResourceEntries[i],&expected,sizeof(expected))==0);
    }
    for (int i=0;i<2;i++) assert(gExpgfxTrackedSourceFrameMasks[i]==(mode==2 ? 0 : ~(u64)0));
    assert(!gExpgfxTextureFreeInProgress && flushes==80 && !warnings); cases++;
}
int main(void) {
    assert(sizeof(void*)==8 && (uintptr_t)objects>UINT32_MAX && (uintptr_t)textures>UINT32_MAX);
    checkTable();
    for (int pool=0;pool<80;pool++) for (int slot=0;slot<25;slot++) checkSlotSelection(pool,slot);
    for (int table=0;table<80;table++) for (int skip=0;skip<2;skip++) for (int flush=0;flush<2;flush++)
    for (int refs=0;refs<3;refs++) for (int resource=0;resource<2;resource++) checkRemove(table,skip,flush,refs,resource);
    for (int owner=-1;owner<3;owner++) for (int wrapper=0;wrapper<3;wrapper++) checkFree(owner,wrapper);
    for (int mode=0;mode<3;mode++) checkReset(mode);
    printf("%d native effect-source lifecycle scenarios passed\n",cases);
}
'''


def harness():
    source = (ROOT / 'src/dlls/engine/10_expgfx/expgfx.c').read_text()
    header = (ROOT / 'include/main/expgfx_internal.h').read_text()
    parts = [PRELUDE, TYPES, 'typedef uint64_t u64;',
             record('include/main/objanim_internal.h', 'ObjAnimComponent'),
             re.search(r'struct GameObject \{.*?\n\};', (ROOT / 'include/game/objects/object.h').read_text(), re.S)[0]]
    parts.append(header[header.index('#define EXPGFX_POOL_COUNT'):header.index('typedef struct ExpgfxBounds')])
    for name, kind in (('ExpgfxFloatWord', 'union'), ('ExpgfxTableEntry', 'struct'),
                       ('ExpgfxResourceEntry', 'struct'), ('ExpgfxSlotStateBits', 'union'),
                       ('ExpgfxQuadVertex', 'struct'), ('ExpgfxSlot', 'struct')):
        parts.append(record('include/main/expgfx_internal.h', name, kind))
    for name in ('gExpgfxSlotPoolBases', 'gExpgfxTrackedPoolSourceIds', 'gExpgfxSlotActiveMasks',
                 'gExpgfxPoolActiveCounts', 'gExpgfxTableEntries', 'gExpgfxResourceEntries',
                 'gExpgfxStaticPoolSlotTypeIds', 'gExpgfxStaticPoolFrameFlags', 'gExpgfxPoolSourceModes',
                 'gExpgfxTrackedSourceFrameMasks'):
        parts.append(re.search(rf'^\w+\*? {name}\[[^\n]+?\]', source, re.M)[0] + ';')
    parts += ['static int gExpgfxTextureFreeInProgress;', SERVICES]
    for name in ('Expgfx_GetSlotTableIndex', 'expgfx_clearResourceTable', 'expgfxRemoveAllBody',
                 'expgfxRemoveAll', 'expgfxRemove', 'expgfx_free', 'expgfx_free2', 'expgfx_ownerFree3',
                 'expgfxGetSlot', 'expgfx_addToTable', 'expgfx_resetAllPools', 'expgfx_onMapSetup'):
        parts.append(function(source, name))
    return '\n'.join(parts + [CHECKS])


class ExpgfxSourceTests(unittest.TestCase):
    def test_native_lifecycle(self):
        with tempfile.TemporaryDirectory(prefix='sfa-expgfx-sources-') as directory:
            source = Path(directory) / 'sources.c'
            source.write_text(harness())
            for optimization in ('-O0', '-O2'):
                with self.subTest(optimization=optimization):
                    exe = Path(directory) / 'sources'
                    subprocess.run(['clang', '-std=c11', optimization, '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=address,undefined', str(source), '-o', str(exe)],
                                   check=True, timeout=30)
                    subprocess.run([str(exe)], check=True, timeout=30,
                                   env={**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1'})


if __name__ == '__main__':
    unittest.main()
