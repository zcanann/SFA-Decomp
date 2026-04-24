#include "ghidra_import.h"
#include "main/dll/FRONT/dll_3E.h"

extern int FUN_80006c30();
extern undefined4 FUN_801177dc();
extern undefined4 FUN_80117818();
extern undefined4 FUN_80117668();
extern int FUN_80118540();
extern undefined4 FUN_80118c88();
extern undefined4 FUN_801197e0();
extern undefined4 FUN_8011981c();
extern undefined4 FUN_80119850();
extern int FUN_801198e8();
extern undefined4 FUN_80119c60();
extern undefined4 FUN_80119c9c();
extern undefined4 FUN_80119cd0();
extern undefined4 FUN_80244758();
extern int FUN_80244820();
extern undefined4 FUN_8024bdfc();
extern undefined4 FUN_8024c910();
extern ushort FUN_8024df24();

extern undefined4 DAT_803a692c;
extern undefined4 DAT_803a694c;
extern undefined4 DAT_803a6980;
extern undefined4 DAT_803a6984;
extern undefined4 DAT_803a69c0;
extern undefined4 DAT_803a6a10;
extern undefined4 DAT_803a6a14;
extern undefined4 DAT_803a6a18;
extern undefined4 DAT_803a6a20;
extern undefined4 DAT_803a6a24;
extern undefined4 DAT_803a6a58;
extern undefined4 DAT_803a6a5c;
extern undefined4 DAT_803a6a5d;
extern undefined4 DAT_803a6a5e;
extern undefined4 DAT_803a6a5f;
extern undefined4 DAT_803a6a60;
extern undefined4 DAT_803a6a64;
extern undefined4 DAT_803a6a68;
extern undefined4 DAT_803a6a6c;
extern undefined4 DAT_803a6a70;
extern undefined4 DAT_803a6a74;
extern undefined4 DAT_803a6a78;
extern undefined4 DAT_803a6a80;
extern undefined4 DAT_803a6a84;
extern undefined4 DAT_803a6a88;
extern undefined4 DAT_803a6a8c;
extern undefined4 DAT_803a6a90;
extern undefined4 DAT_803a6a94;
extern undefined4 DAT_803a6a98;
extern undefined4 DAT_803a6aa0;
extern undefined4 DAT_803a6aa4;
extern undefined4 DAT_803a6aa8;
extern undefined4 DAT_803a6aac;
extern undefined4 DAT_803a6ab0;
extern undefined4* DAT_803de2e4;
extern undefined4 DAT_803de300;

/*
 * --INFO--
 *
 * Function: FUN_8011846c
 * EN v1.0 Address: 0x8011846C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80118714
 * EN v1.1 Size: 944b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011846c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80118470
 * EN v1.0 Address: 0x80118470
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x80118AC4
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80118470(void)
{
  int iVar1;
  int iVar2;
  int local_18 [5];
  
  if ((DAT_803a6a58 != 0) && (DAT_803a6a5c != '\0')) {
    DAT_803a6a5d = 0;
    DAT_803a6a5c = '\0';
    FUN_8024c910(DAT_803de2e4);
    if (DAT_803a6a68 == 0) {
      FUN_8024bdfc((int *)&DAT_803a69c0);
      FUN_801197e0();
    }
    FUN_80119c60();
    if (DAT_803a6a5f != '\0') {
      FUN_801177dc();
    }
    do {
      iVar2 = FUN_80244820((int *)&DAT_803a692c,local_18,0);
      iVar1 = local_18[0];
      if (iVar2 != 1) {
        iVar1 = 0;
      }
    } while (iVar1 != 0);
    DAT_803a6a94 = DAT_803a6a98;
    DAT_803a6aa0 = 0;
    DAT_803a6a60 = 0;
    DAT_803a6a64 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80118524
 * EN v1.0 Address: 0x80118524
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x80118BA8
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80118524(void)
{
  if ((DAT_803a6a58 != 0) && ((DAT_803a6a5c == '\x01' || (DAT_803a6a5c == '\x04')))) {
    DAT_803a6a5c = 2;
    DAT_803a6a88 = 0;
    DAT_803a6a8c = 0;
    DAT_803a6a84 = 0xffffffff;
    DAT_803a6a80 = 0xffffffff;
    return 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80118574
 * EN v1.0 Address: 0x80118574
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80118C08
 * EN v1.1 Size: 552b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_80118574(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,undefined param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}
