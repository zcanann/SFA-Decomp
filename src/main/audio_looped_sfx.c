/* Looped object sounds: indexed parallel arrays and keep-alive tracking. */
#include "main/audio/sfx_looped_object_api.h"
#include "main/audio/sfx_object_query_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_object_api.h"
#include "game/objects/object.h"
#include "string.h"

#define SFX_LOOPED_OBJECT_CAPACITY         0x80
#define SFX_LOOPED_OBJECT_SOUND_FLAG_ALIVE 1
#define SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN  2

u16 gSfxLoopedObjectSoundCount;
GameObject* gSfxLoopedObjectSoundObjects[SFX_LOOPED_OBJECT_CAPACITY];
u16 gSfxLoopedObjectSoundIds[SFX_LOOPED_OBJECT_CAPACITY];
u8 gSfxLoopedObjectSoundFlags[SFX_LOOPED_OBJECT_CAPACITY];

void Sfx_AddLoopedObjectSound(GameObject* obj, u16 sfxId) {
    s16 i;
    GameObject** objectIt;
    u16* idIt;
    s32 count;
    int found;

    i = 0;
    objectIt = gSfxLoopedObjectSoundObjects;
    idIt = gSfxLoopedObjectSoundIds;
    count = gSfxLoopedObjectSoundCount;
    for (; i < count || (found = 0, 0); i++) {
        if ((*objectIt == obj) && (sfxId == *idIt)) {
            found = 1;
            break;
        }
        objectIt++;
        idIt++;
    }

    if ((found == 0) && (count != sizeof(gSfxLoopedObjectSoundFlags))) {
        gSfxLoopedObjectSoundObjects[count] = obj;
        gSfxLoopedObjectSoundIds[count] = sfxId;
        gSfxLoopedObjectSoundFlags[count] = 0;
        gSfxLoopedObjectSoundCount++;
        Sfx_PlayFromObject(obj, sfxId);
    }
}

void Sfx_RemoveLoopedObjectSound(GameObject* obj, u16 sfxId) {
    s16 i;
    int index;
    int index2;
    u16 sz;

    i = (s16)(gSfxLoopedObjectSoundCount - 1);
    for (; i >= 0; i--) {
        if (gSfxLoopedObjectSoundObjects[i] == obj && sfxId == gSfxLoopedObjectSoundIds[i]) {
            gSfxLoopedObjectSoundCount--;
            sz = (u16)((gSfxLoopedObjectSoundCount - (index = (u16)i)) * sizeof(GameObject*));
            memmove(gSfxLoopedObjectSoundObjects + index, gSfxLoopedObjectSoundObjects + (index2 = index + 1), sz);
            memmove((u16*)gSfxLoopedObjectSoundIds + index, (u16*)gSfxLoopedObjectSoundIds + index2,
                    (u16)((gSfxLoopedObjectSoundCount - index) << 1));
            memmove(gSfxLoopedObjectSoundFlags + index, gSfxLoopedObjectSoundFlags + index2,
                    (u16)(gSfxLoopedObjectSoundCount - index));
            Sfx_StopFromObject(obj, sfxId);
            return;
        }
    }
}

void Sfx_RemoveLoopedObjectSoundForObject(GameObject* obj) {
    int index;
    int index2;
    s16 i;
    u16 sz;

    i = (s16)(gSfxLoopedObjectSoundCount - 1);
    for (; i >= 0; i--) {
        if (gSfxLoopedObjectSoundObjects[i] == obj) {
            Sfx_StopFromObject(obj, gSfxLoopedObjectSoundIds[i]);
            gSfxLoopedObjectSoundCount--;
            sz = (u16)((gSfxLoopedObjectSoundCount - (index = (u16)i)) * sizeof(GameObject*));
            memmove(gSfxLoopedObjectSoundObjects + index, gSfxLoopedObjectSoundObjects + (index2 = index + 1), sz);
            memmove((u16*)gSfxLoopedObjectSoundIds + index, (u16*)gSfxLoopedObjectSoundIds + index2,
                    (u16)((gSfxLoopedObjectSoundCount - index) << 1));
            memmove(gSfxLoopedObjectSoundFlags + index, gSfxLoopedObjectSoundFlags + index2,
                    (u16)(gSfxLoopedObjectSoundCount - index));
            return;
        }
    }
}

void Sfx_KeepAliveLoopedObjectSound(GameObject* obj, u16 sfxId) {
    Sfx_KeepAliveLoopedObjectSoundLimited(obj, sfxId, 0);
}

void Sfx_KeepAliveLoopedObjectSoundLimited(GameObject* obj, u16 sfxId, u16 limit) {
    u8* flags = gSfxLoopedObjectSoundFlags;
    s32 count;
    u16 sameSfxCount;
    u16* ip;
    GameObject** op;
    GameObject** objects;
    u16* ids;
    s16 j;
    int found;
    s16 i;

    count = gSfxLoopedObjectSoundCount;
    sameSfxCount = 0;
    i = 0;
    ids = gSfxLoopedObjectSoundIds;
    ip = ids;
    objects = gSfxLoopedObjectSoundObjects;
    op = objects;
    for (; i < count; i++) {
        if (sfxId == *ip) {
            if (limit != 0) {
                sameSfxCount++;
            }
            if (*op == obj) {
                flags[i] |= SFX_LOOPED_OBJECT_SOUND_FLAG_ALIVE | SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN;
                return;
            }
        }
        ip++;
        op++;
    }

    if (sameSfxCount <= limit) {
        for (j = 0; j < count || (found = 0, 0); j++) {
            if (*objects == obj && sfxId == *ids) {
                found = 1;
                break;
            }
            objects++;
            ids++;
        }

        if ((found == 0) && (count != sizeof(gSfxLoopedObjectSoundFlags))) {
            gSfxLoopedObjectSoundObjects[count] = obj;
            gSfxLoopedObjectSoundIds[count] = sfxId;
            flags[count] = 0;
            gSfxLoopedObjectSoundCount++;
            Sfx_PlayFromObject(obj, sfxId);
        }
    }

    if ((u32)count != gSfxLoopedObjectSoundCount) {
        flags[count] |= SFX_LOOPED_OBJECT_SOUND_FLAG_ALIVE | SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN;
    }
}

void Sfx_UpdateLoopedObjectSounds(void) {
    u16 index;
    s16 i;
    int index2;
    GameObject* obj;
    int removeSound;
    u16 sz;

    i = (s16)(gSfxLoopedObjectSoundCount - 1);
    for (; i >= 0; i--) {
        removeSound = 0;
        if (((gSfxLoopedObjectSoundFlags[i] & SFX_LOOPED_OBJECT_SOUND_FLAG_ALIVE) != 0) &&
            ((gSfxLoopedObjectSoundFlags[i] & SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN) == 0)) {
            removeSound = 1;
        }
        obj = gSfxLoopedObjectSoundObjects[i];
        if (((obj != 0) && ((obj->objectFlags & OBJECT_OBJFLAG_FREED) != 0)) || removeSound) {
            Sfx_StopFromObject(obj, gSfxLoopedObjectSoundIds[i]);
            gSfxLoopedObjectSoundCount--;
            sz = (u16)((gSfxLoopedObjectSoundCount - (index = i)) * sizeof(GameObject*));
            memmove(gSfxLoopedObjectSoundObjects + index, gSfxLoopedObjectSoundObjects + (index2 = index + 1), sz);
            memmove((u16*)gSfxLoopedObjectSoundIds + index, (u16*)gSfxLoopedObjectSoundIds + index2,
                    (u16)((gSfxLoopedObjectSoundCount - index) << 1));
            memmove(gSfxLoopedObjectSoundFlags + index, gSfxLoopedObjectSoundFlags + index2,
                    (u16)(gSfxLoopedObjectSoundCount - index));
        } else {
            gSfxLoopedObjectSoundFlags[i] &= ~SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN;
        }
    }

    {
        s16 i2;
        u16* ip2;
        GameObject** op2;
        for (i2 = 0, ip2 = gSfxLoopedObjectSoundIds, op2 = gSfxLoopedObjectSoundObjects;
             i2 < gSfxLoopedObjectSoundCount; i2++) {
            if (Sfx_IsPlayingFromObject(*op2, *ip2) == 0) {
                Sfx_PlayFromObject(*op2, *ip2);
            }
            ip2++;
            op2++;
        }
    }
}

void Sfx_ClearLoopedObjectSounds(void) {
    gSfxLoopedObjectSoundCount = 0;
}
