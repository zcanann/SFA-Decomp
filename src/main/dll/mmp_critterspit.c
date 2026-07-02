/*
 * mmp_critterspit - Tricky's "is this critter worth eating?" decision.
 *
 * trickyFoodFn_8013db3c is queried with Tricky (arg1) and a candidate
 * critter (arg2). It returns:
 *   0 - not interested,
 *   1 - interested (critter is valid prey here),
 *   2 - interested AND within eating range.
 *
 * A critter is rejected outright while another object of group 0x53 is
 * nearby. Otherwise critters of type != 3 are accepted depending on the
 * level object's map cell: cell 0x38 gates acceptance behind a set of
 * game bits, any other cell flags the critter's per-instance cooldown
 * (the 4-bit mode field packed at byte 0x58) and accepts it. The final
 * range test promotes a "1" result to "2" when the critter sits within
 * lbl_803E24C4 squared units of Tricky.
 */
#include "main/dll/baddie/MMP_critterspit.h"
#include "main/game_object.h"
#include "main/gamebits.h"

#define MMPCRITTERSPIT_OBJFLAG_PARENT_SLACK 0x1000
extern f32 lbl_803E242C; /* initial search radius for ObjGroup_FindNearestObject */
extern f32 lbl_803E24C4; /* squared eating-range threshold */
extern u8* ObjGroup_FindNearestObject(int kind, u8* self, f32* outDist);
extern int coordsToMapCell(u8* p, f32 a, f32 b);
extern f32 vec3f_distanceSquared(f32* a, f32* b);

/* per-critter packed flags at byte 0x58; bits 27..30 hold a countdown mode */
struct CritterFlags
{
    u32 pad_high : 3;
    u32 mode : 4;
    u32 pad_low : 1;
};

int trickyFoodFn_8013db3c(u8* tricky, u8* critter)
{
    int result = 0;
    f32 dist = lbl_803E242C;
    struct CritterFlags* flags = (struct CritterFlags*)&critter[0x58];

    if (flags->mode != 0)
    {
        flags->mode--;
        result = 1;
    }

    if (ObjGroup_FindNearestObject(0x53, tricky, &dist) != NULL)
    {
        return 0;
    }

    if ((s8)critter[0xD] != 3)
    {
        u8* levelObj = (u8*)*(u32*)(critter + 4);

        if ((((GameObject*)levelObj)->objectFlags & MMPCRITTERSPIT_OBJFLAG_PARENT_SLACK) != 0)
        {
            if (coordsToMapCell(levelObj, ((GameObject*)tricky)->anim.localPosX,
                                ((GameObject*)tricky)->anim.localPosZ) == 0x38)
            {
                if ((GameBit_Get(0x385) == 0) && (GameBit_Get(0x384) != 0))
                {
                    if ((GameBit_Get(0xC1) != 0) || (GameBit_Get(0x12E) != 0))
                    {
                        result = 1;
                    }
                }
            }
            else
            {
                flags->mode = 0x1F;
                result = 1;
            }
        }
    }

    if (result == 1)
    {
        u8* levelObj = (u8*)*(u32*)(critter + 4);

        if (vec3f_distanceSquared(&((GameObject*)levelObj)->anim.worldPosX,
                                  &((GameObject*)tricky)->anim.worldPosX) < lbl_803E24C4)
        {
            return 2;
        }
    }
    return result;
}
