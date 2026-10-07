#!/usr/bin/env python3
"""Exercise the production line-query coordinator with native object pointers.

Transforms and inner sweeps are controlled services. This covers coordinate
handoff, filtering, result conversion and dynamic-cache ownership, not the
inner line/circle intersection arithmetic.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

from test_track_line_storage import records
from test_render_queue import record
from test_model_instance_layout import function

ROOT = Path(__file__).resolve().parents[1]
EXTRA = r'''
typedef struct ModelFileHeader ModelFileHeader;
typedef struct ModelJointWork ModelJointWork;
typedef struct ObjAnimState ObjAnimState;
typedef struct ModelRenderOpTextureRefs ModelRenderOpTextureRefs;
typedef struct GroundShadowQuad GroundShadowQuad;
#define OBJHITS_PRIORITY_HIT_COUNT 3
'''
SERVICES = r'''
static MapDynamicSlot cache[64]; static MapDynamicSlot* gMapDynamicSlots=cache;
static u8 gTrackSweepHitCount;
static GameObject objects[4],*list[1],*source,*parent,*target;
static ObjDef definition;
static ObjHitsPriorityState priority;
static ObjModel model,*banks[1]; static unsigned char modelFileToken;
static IntersectLine line;
static int warnings,sweeps,objectSweeps,cases,hitMode;
static float expectedStart[3],expectedEnd[3],expectedLocalStart[3],expectedLocalEnd[3],resultWorldEnd[3];
static TrackLineIntersectResult latest;
static const char sTrackNoFreeLastLineError[]="NO FREE LAST LINE\n";
static void debugPrintf(const char* text) { assert(text==sTrackNoFreeLastLineError); warnings++; }
static int modelFileHeaderGetCullDistance(ModelFileHeader* file) { assert(file==(void*)&modelFileToken); return 0; }
static GameObject** objGetAllOfType(int type,int* count) { assert(type==6); *count=1; return list; }
static void transform(GameObject* object,const float* input,float* output,int inverse) {
    float x=input[0],y=input[1],z=input[2];
    if (inverse) {
        x-=object->anim.worldPosX; y-=object->anim.worldPosY; z-=object->anim.worldPosZ;
        if (object->anim.rotY) { float old=x; x=-z; z=old; }
    } else {
        if (object->anim.rotY) { float old=x; x=z; z=-old; }
        x+=object->anim.worldPosX; y+=object->anim.worldPosY; z+=object->anim.worldPosZ;
    }
    output[0]=x; output[1]=y; output[2]=z;
}
static void Obj_TransformLocalPointToWorld(float x,float y,float z,float* ox,float* oy,float* oz,GameObject* object) {
    assert((object==parent || object==target) && (uintptr_t)object>UINT32_MAX);
    float input[3]={x,y,z},output[3]; transform(object,input,output,0); *ox=output[0]; *oy=output[1]; *oz=output[2];
}
static void Obj_TransformWorldPointToLocal(float x,float y,float z,float* ox,float* oy,float* oz,GameObject* object) {
    assert((object==parent || object==target) && (uintptr_t)object>UINT32_MAX);
    float input[3]={x,y,z},output[3]; transform(object,input,output,1); *ox=output[0]; *oy=output[1]; *oz=output[2];
}
static void vectorEqual(const float* a,const float* b) {
    for (int i=0;i<3;i++) assert(fabsf(a[i]-b[i])<0.0001f);
}
static int trackSweepCircleAgainstLines(float* start,float* end,float radius,int flags,TrackLineIntersectResult* out,
                                        GameObject* object,s8 mask,s8 segment,s8 tolerance,GameObject* owner) {
    assert(radius==3 && flags==2 && mask==-7 && segment==-1 && tolerance==-3 && owner==source);
    assert(object==NULL || object==target); sweeps++;
    if (object) {
        objectSweeps++; vectorEqual(start,expectedLocalStart); vectorEqual(end,expectedLocalEnd);
    } else { vectorEqual(start,expectedStart); vectorEqual(end,expectedEnd); }
    int hit=(hitMode & (object ? 1 : 2))!=0;
    if (hit) {
        end[0]+=2; end[2]-=3; gTrackSweepHitCount++;
        if (out) {
            out->object=object; out->lineStartX=1; out->lineStartY=2; out->lineStartZ=3;
            out->lineEndX=4; out->lineEndY=5; out->lineEndZ=7;
            out->upperY0=8; out->upperY1=12; out->surfaceType=4; out->kind=2;
            latest=*out;
        }
    }
    if (object) {
        memcpy(expectedLocalEnd,end,12);
        if (hit) transform(object,end,expectedEnd,0);
    } else memcpy(resultWorldEnd,end,12);
    return hit;
}
'''
CHECKS = r'''
static void plane(float x0,float z0,float x1,float z1,float* nx,float* nz,float* d) {
    double x=z1-z0,z=x0-x1,length=hypot(x,z);
    *nx=x/length; *nz=z/length; *d=-(*nx*x0+*nz*z0);
}
static void check(int parentMode,int filter,int cacheMode,int hits,int output) {
    memset(objects,0,sizeof(objects)); memset(cache,0,sizeof(cache)); memset(&definition,0,sizeof(definition));
    memset(&priority,0,sizeof(priority)); memset(&model,0,sizeof(model));
    source=parentMode==0 ? NULL : objects; parent=parentMode>=2 ? objects+2 : NULL;
    target=filter==1 ? source : objects+1; list[0]=target; assert(target);
    if (source) source->anim.parent=parent;
    if (parent) { parent->anim.worldPosX=11; parent->anim.worldPosY=20; parent->anim.worldPosZ=30; parent->anim.rotY=parentMode==3; }
    target->anim.worldPosX=-15; target->anim.worldPosY=8; target->anim.worldPosZ=5; target->anim.rotY=1;
    float start[3]={1,2,3},end[3]={filter==6 ? 201 : 4,5,6},originalEnd[3]; memcpy(originalEnd,end,12);
    if (parent) { transform(parent,start,expectedStart,0); transform(parent,end,expectedEnd,0); }
    else { memcpy(expectedStart,start,12); memcpy(expectedEnd,end,12); }
    target->anim.localPosX=filter==6 ? expectedEnd[0] : expectedStart[0];
    target->anim.localPosY=expectedStart[1]; target->anim.localPosZ=filter==6 ? expectedEnd[2] : expectedStart[2];
    if (filter==5) target->anim.localPosX+=1000;
    target->anim.transformMatrixIndex=filter==2 ? -1 : 0;
    definition.intersectionLines=filter==3 ? NULL : &line; target->anim.modelInstance=&definition;
    priority.flags=filter==4 ? 0 : 1; target->anim.hitReactState=(void*)&priority;
    banks[0]=&model; model.file=(void*)&modelFileToken; target->anim.modelBanks=banks;
    transform(target,expectedStart,expectedLocalStart,1); transform(target,expectedEnd,expectedLocalEnd,1);
    if (cacheMode>=2) {
        for (int i=0;i<64;i++) cache[i]=(MapDynamicSlot){objects+3,objects+3,{0,0,0},2,7,{0,0}};
        if (cacheMode==2) {
            cache[63]=(MapDynamicSlot){source,target,{70,80,90},2,7,{0,0}};
            expectedLocalStart[0]=70; expectedLocalStart[1]=80; expectedLocalStart[2]=90;
        }
    }
    MapDynamicSlot before[64]; memcpy(before,cache,sizeof(before));
    TrackLineIntersectResult result; memset(&result,0x39,sizeof(result)); TrackLineIntersectResult expected=result;
    int eligible=filter==0 || filter==6;
    warnings=sweeps=objectSweeps=0; hitMode=hits;
    int count=trackGetLineIntersect(start,end,3,2,output ? &result : NULL,source,-7,-1,cacheMode ? 7 : 255,-3);
    assert(count==(eligible && (hits&1) ? 1 : 0)+((hits&2) ? 1 : 0));
    assert(sweeps==1+eligible && objectSweeps==eligible && warnings==(eligible && cacheMode==3));
    if (count) {
        float expectedResult[3];
        if (parent) transform(parent,resultWorldEnd,expectedResult,1); else memcpy(expectedResult,resultWorldEnd,12);
        vectorEqual(end,expectedResult);
    } else vectorEqual(end,originalEnd);
    if (output) {
        if (count) {
            expected=latest;
            plane(1,3,4,7,&expected.sourceNormalX,&expected.sourceNormalZ,&expected.sourceNormalW); expected.sourceNormalY=0;
            float from[3]={1,2,3},to[3]={4,5,7};
            if (latest.object) { transform(latest.object,from,from,0); transform(latest.object,to,to,0); }
            if (parent) { transform(parent,from,from,1); transform(parent,to,to,1); }
            expected.lineStartX=from[0]; expected.lineStartY=from[1]; expected.lineStartZ=from[2];
            expected.lineEndX=to[0]; expected.lineEndY=to[1]; expected.lineEndZ=to[2];
            plane(from[0],from[2],to[0],to[2],&expected.normalX,&expected.normalZ,&expected.normalW); expected.normalY=0;
            expected.upperY0=from[1]+6; expected.upperY1=to[1]+7;
            assert(result.object==expected.object);
            const float* a=&result.lineStartX; const float* b=&expected.lineStartX;
            for (int i=0;i<18;i++) assert(fabsf(a[i]-b[i])<0.0001f);
            assert(result.adjacentLine0==expected.adjacentLine0 && result.adjacentLine1==expected.adjacentLine1);
            assert(result.surfaceType==4 && result.kind==2 && result.flags==expected.flags && result.pad53==expected.pad53);
        } else {
            expected.surfaceType=expected.kind=-1; assert(memcmp(&result,&expected,sizeof(result))==0);
        }
    }
    int changed=eligible && (cacheMode==1 || cacheMode==2) ? (cacheMode==1 ? 0 : 63) : -1;
    for (int i=0;i<64;i++) {
        if (i==changed) {
            assert(cache[i].owner==source && cache[i].target==target && cache[i].cooldown==2 && cache[i].querySlot==7);
            vectorEqual(&cache[i].cachedLocalEnd.x,expectedLocalEnd);
        } else assert(memcmp(&cache[i],&before[i],sizeof(cache[i]))==0);
    }
    cases++;
}
int main(void) {
    assert(sizeof(void*)==8 && (uintptr_t)objects>UINT32_MAX);
    for (int parent=0;parent<4;parent++) for (int filter=0;filter<7;filter++) {
        if (!parent && filter==1) continue;
        for (int cache=0;cache<4;cache++) for (int hit=0;hit<4;hit++) for (int out=0;out<2;out++)
            check(parent,filter,cache,hit,out);
    }
    printf("%d native collision-line query scenarios passed\n",cases);
}
'''


def harness():
    source = (ROOT / 'src/main/track_dolphin.c').read_text()
    parts = [records(), EXTRA, record('include/main/model.h', 'ObjModel'),
             record('include/main/objhits_types.h', 'ObjHitsPriorityState'),
             record('include/main/track_line_intersect_result.h', 'TrackLineIntersectResult'), SERVICES]
    for name in ('trackFindDynamicSlot', 'trackAllocDynamicSlot', 'trackGetLineIntersect'):
        parts.append(function(source, name))
    return '\n'.join(parts + [CHECKS])


class TrackLineQueryTests(unittest.TestCase):
    def test_native_query(self):
        with tempfile.TemporaryDirectory(prefix='sfa-track-line-query-') as directory:
            source = Path(directory) / 'query.c'
            source.write_text(harness())
            for optimization in ('-O0', '-O2'):
                with self.subTest(optimization=optimization):
                    exe = Path(directory) / 'query'
                    subprocess.run(['clang', '-std=c11', optimization, '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=address,undefined', str(source), '-o', str(exe)],
                                   check=True, timeout=30)
                    subprocess.run([str(exe)], check=True, timeout=30,
                                   env={**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1'})


if __name__ == '__main__':
    unittest.main()
