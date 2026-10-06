#!/usr/bin/env python3
"""Exercise the production object-message queue with native pointers and an independent FIFO model."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r'''
#include <assert.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t u32;
typedef int16_t s16;
typedef float f32;
typedef struct ObjMsgQueue ObjMsgQueue;
/* Only the external engine fields used by the queue; deliberately different host offsets. */
typedef struct GameObject {
    void* hostPrefix[3];
    struct { float worldPosX, worldPosY, worldPosZ; s16 classId, romDefNo; } anim;
    ObjMsgQueue* msgQueue;
} GameObject;
#define STATIC_ASSERT(x)
static void* mmAlloc(int bytes, int tag, int name);
static GameObject** ObjList_GetObjects(int* start, int* count);
static float Vec_distance(float* a, float* b);
static void debugPrintf(char* format, ...);
'''
CHECKS = r'''
enum { OBJECTS = 9, MAX_MESSAGES = 20 };
typedef struct { u32 id; GameObject* sender; void* arg; } Message;
typedef struct { int capacity, count; Message messages[MAX_MESSAGES]; } Model;
typedef struct { u32 id; int classId, defNo, senderDefNo; } Warning;
static GameObject objects[OBJECTS];
static GameObject* list[OBJECTS];
static Model model[OBJECTS];
static Warning warnings[OBJECTS];
static int warningCount, warningIndex, startIndex, operations, allocationCount, expectedBytes;
static unsigned char payloads[OBJECTS][17];
static u32 randomState = 0x837ed19;
static u32 randomWord(void) {
    randomState ^= randomState << 13; randomState ^= randomState >> 17; randomState ^= randomState << 5;
    return randomState;
}
static void* mmAlloc(int bytes, int tag, int name) {
    assert(bytes == expectedBytes && tag == 14 && name == 0);
    void* p = malloc(bytes); assert(p && (uintptr_t)p > UINT32_MAX);
    memset(p,0xa5,bytes); allocationCount++; return p;
}
static GameObject** ObjList_GetObjects(int* start, int* count) {
    *start = startIndex; *count = OBJECTS; return list;
}
static float Vec_distance(float* a, float* b) {
    float x=a[0]-b[0], y=a[1]-b[1], z=a[2]-b[2]; return sqrtf(x*x+y*y+z*z);
}
static void debugPrintf(char* format, ...) {
    assert(format == sObjMsgOverflowInObjectWarning && warningIndex < warningCount);
    Warning w=warnings[warningIndex++]; va_list args; va_start(args,format);
    assert(va_arg(args,u32) == w.id); assert(va_arg(args,int) == w.classId);
    assert(va_arg(args,int) == w.defNo); assert(va_arg(args,int) == w.senderDefNo);
    va_end(args);
}
static void check(void) {
    assert(warningIndex == warningCount);
    for (int i=0;i<OBJECTS;i++) {
        Model* m=&model[i]; ObjMsgQueue* q=objects[i].msgQueue;
        if (!m->capacity) { assert(!q); continue; }
        assert(q->words[OBJMSG_COUNT].value == (u32)m->count);
        assert(q->words[OBJMSG_CAPACITY].value == (u32)m->capacity);
        for (int j=0;j<m->count;j++) {
            ObjMsgWord* w=&q->words[2+3*j]; Message e=m->messages[j];
            assert(w[0].value == e.id && w[1].sender == e.sender && w[2].param == e.arg);
        }
    }
    operations++;
}
static int append(GameObject* receiver, Message message) {
    if (!receiver) return 0;
    Model* m=&model[receiver-objects];
    if (!m->capacity) return 0;
    if (m->count == m->capacity) {
        assert(message.sender && warningCount < OBJECTS);
        warnings[warningCount++]=(Warning){message.id,receiver->anim.classId,receiver->anim.romDefNo,
                                          message.sender->anim.romDefNo};
        return 0;
    }
    m->messages[m->count++]=message; return m->count;
}
static void send(GameObject* receiver, Message message) {
    warningCount=warningIndex=0;
    int result=append(receiver,message);
    assert(ObjMsg_SendToObject(receiver,message.id,message.sender,message.arg) == (u32)result);
    check();
}
static void receive(GameObject* receiver, int pop, int mask) {
    warningCount=warningIndex=0;
    /* Guards also catch writes at the old out-argument widths or positions. */
    struct { uintptr_t before; u32 id; uintptr_t after; } id={0xfeed,0xabcdef01,0xbeef};
    struct { uintptr_t before; GameObject* value; uintptr_t after; } sender={0xfeed,&objects[8],0xbeef};
    struct { uintptr_t before; void* value; uintptr_t after; } arg={0xfeed,&payloads[8][16],0xbeef};
    Model* m=receiver ? &model[receiver-objects] : NULL;
    int result=m && m->count; Message expected={id.id,sender.value,arg.value};
    if (result) {
        Message front=m->messages[0];
        if (mask&1) expected.id=front.id;
        if (mask&2) expected.sender=front.sender;
        if (mask&4) expected.arg=front.arg;
        if (pop) {
            memmove(m->messages,m->messages+1,(--m->count)*sizeof(Message));
        }
    }
    int actual=(pop ? ObjMsg_Pop : ObjMsg_Peek)(receiver,mask&1 ? &id.id : NULL,
                                              mask&2 ? &sender.value : NULL,mask&4 ? &arg.value : NULL);
    assert(actual == result && id.id == expected.id && sender.value == expected.sender && arg.value == expected.arg);
    assert(id.before == 0xfeed && id.after == 0xbeef && sender.before == 0xfeed && sender.after == 0xbeef);
    assert(arg.before == 0xfeed && arg.after == 0xbeef); check();
}
static void broadcast(int nearby, int target, float radius, u32 flags, Message message) {
    warningCount=warningIndex=0;
    for (int i=startIndex;i<OBJECTS;i++) {
        GameObject* o=list[i];
        if ((flags&1) && o == message.sender) continue;
        int id=nearby || (flags&4) ? o->anim.romDefNo : o->anim.classId;
        int filter=nearby ? (s16)target : target;
        if (!(flags&2) && id != filter) continue;
        if (nearby) {
            double dx=(double)o->anim.worldPosX-message.sender->anim.worldPosX;
            double dy=(double)o->anim.worldPosY-message.sender->anim.worldPosY;
            double dz=(double)o->anim.worldPosZ-message.sender->anim.worldPosZ;
            if (!(sqrt(dx*dx+dy*dy+dz*dz) < radius)) continue;
        }
        append(o,message);
    }
    if (nearby) ObjMsg_SendToNearbyObjects(target,radius,flags,message.sender,message.id,message.arg);
    else ObjMsg_SendToObjects(target,flags,message.sender,message.id,message.arg);
    check();
}
static void drain(void) {
    for (int i=0;i<OBJECTS;i++) while (model[i].count) receive(&objects[i],1,7);
}
int main(void) {
    assert(sizeof(void*) == 8 && sizeof(ObjMsgWord) == sizeof(void*));
    assert((uintptr_t)objects > UINT32_MAX && (uintptr_t)payloads > UINT32_MAX);
    const int capacities[OBJECTS]={1,2,5,20,3,0,1,4,8};
    ObjMsg_AllocQueue(NULL,4); ObjMsg_AllocQueue(&objects[0],0); assert(allocationCount == 0);
    for (int i=0;i<OBJECTS;i++) {
        list[i]=&objects[i]; objects[i].anim.classId=i%3; objects[i].anim.romDefNo=i%2 ? 17 : -7;
        objects[i].anim.worldPosX=3*i; objects[i].anim.worldPosY=4*i;
        expectedBytes=(2+3*capacities[i])*sizeof(void*);
        ObjMsg_AllocQueue(&objects[i],capacities[i]); model[i].capacity=capacities[i];
        int saved=allocationCount;
        ObjMsg_AllocQueue(&objects[i],capacities[i]); assert(allocationCount == saved);
    }
    Message message={0x7000a,&objects[0],&payloads[0][1]};
    send(NULL,message); send(&objects[5],message);
    for (int mask=0;mask<8;mask++) {
        receive(NULL,0,mask); receive(NULL,1,mask);
        receive(&objects[5],0,mask); receive(&objects[0],1,mask);
        send(&objects[0],message); receive(&objects[0],0,mask); receive(&objects[0],1,mask);
    }
    /* Full queues, every compaction position, pointer arguments and encoded integers. */
    for (int i=0;i<21;i++) send(&objects[3],(Message){(u32)i,&objects[i%OBJECTS],&payloads[i%OBJECTS][i%17]});
    drain();
    send(&objects[0],(Message){1,NULL,NULL}); receive(&objects[0],1,7);
    for (int nearby=0;nearby<2;nearby++) for (int flags=0;flags<8;flags++) {
        for (int target=0;target<4;target++) for (int distance=0;distance<4;distance++) {
            drain(); startIndex=target%3;
            broadcast(nearby,(int[]){0,17,-7,65529}[target],(float[]){-1,0,5,41}[distance],
                      0xabcd0000u|flags,message);
        }
    }
    for (int i=0;i<5000;i++) {
        u32 r=randomWord(); int which=(r>>8)%OBJECTS;
        message=(Message){r,&objects[(r>>16)%OBJECTS],r&1 ? &payloads[which][r%17] : (void*)(uintptr_t)(r>>2)};
        startIndex=(r>>24)%OBJECTS;
        switch (r%4) {
        case 0: send(&objects[which],message); break;
        case 1: receive(&objects[which],(r>>4)&1,(r>>5)&7); break;
        default: broadcast(r&1,(r>>12)&1 ? 17 : -7,(r>>2)%50,r>>20,message); break;
        }
    }
    drain(); for (int i=0;i<OBJECTS;i++) free(objects[i].msgQueue);
    printf("%d object-message operations agree with the FIFO model\n",operations);
}
'''


def source():
    text = (ROOT / "src/main/objlib.c").read_text()
    flags = "\n".join(re.findall(r"^#define OBJMSG_SEND_.*$", text, re.M))
    storage = text[text.index("typedef union ObjMsgWord"):text.index("int Obj_IsObjectAlive")]
    api = (ROOT / "include/main/obj_message.h").read_text()
    api = re.sub(r'^#include .*$', '', api, flags=re.M)
    return PRELUDE + api + flags + "\n" + storage + CHECKS


class NativeObjectMessages(unittest.TestCase):
    def test_fifo(self):
        compiler = shutil.which("clang")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix="sfa-objmsg-") as work:
            path = Path(work) / "queue.c"
            path.write_text(source())
            for level in ("-O0", "-O2"):
                with self.subTest(optimization=level):
                    binary = Path(work) / "queue"
                    subprocess.run([compiler, "-std=c11", level, "-g", "-fno-common", "-Wall", "-Wextra",
                                    "-Werror", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                                    str(path), "-o", str(binary)], check=True, timeout=30)
                    subprocess.run([str(binary)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
