#include "ghidra_import.h"
#include "main/dll/door.h"

extern undefined4 FUN_80006b4c();
extern uint FUN_80017690();
extern void fn_8003B8F4(int obj,float param_2);
extern undefined4 sfxplayer_updateState();

extern undefined4 DAT_803add98;
extern undefined4 DAT_803add9c;
extern undefined4 DAT_803adda0;
extern undefined4 DAT_803adda4;
extern undefined4 DAT_803adda8;
extern undefined4 DAT_803addac;
extern undefined4 DAT_803addb0;
extern undefined4 DAT_803addb4;
extern f32 lbl_803E6490;

/*
 * --INFO--
 *
 * Function: dfptargetblock_resolveCollisionPoints
 * EN v1.0 Address: 0x80208508
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802085F4
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfptargetblock_resolveCollisionPoints(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: dfptargetblock_getExtraSize
 * EN v1.0 Address: 0x80208660
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8020874C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfptargetblock_getExtraSize(void)
{
  return 0x6c;
}

/*
 * --INFO--
 *
 * Function: dfptargetblock_func08
 * EN v1.0 Address: 0x80208668
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80208754
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfptargetblock_func08(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: dfptargetblock_free
 * EN v1.0 Address: 0x80208670
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020875C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfptargetblock_free(void)
{
}

/*
 * --INFO--
 *
 * Function: dfptargetblock_render
 * EN v1.0 Address: 0x80208674
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x80208760
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfptargetblock_render(int obj)
{
  int state;

  state = *(int *)(obj + 0xb8);
  if (((*(u8 *)(state + 0x6b) == 0) && (*(u8 *)(state + 0x6a) != 0)) &&
      (*(u8 *)(state + 0x69) != 4)) {
    fn_8003B8F4(obj,lbl_803E6490);
  }
}
