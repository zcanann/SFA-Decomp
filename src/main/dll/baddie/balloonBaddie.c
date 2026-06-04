#include "ghidra_import.h"
#include "main/dll/baddie/balloonBaddie.h"

extern undefined4 FUN_80006954();
extern undefined4 FUN_8000695c();
extern undefined4 FUN_80006960();
extern undefined4 FUN_80006984();
extern undefined4 FUN_80006988();
extern undefined4 FUN_800069a8();
extern undefined4 FUN_800069b0();
extern undefined4 FUN_800069b8();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_800069d4();
extern double FUN_800069f8();
extern undefined4 FUN_80006a00();
extern uint GameBit_Get(int eventId);
extern int FUN_800176d0();
extern int FUN_8001792c();
extern int FUN_80017a54();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_8003b878();
extern int FUN_80042838();
extern undefined4 FUN_80051fc4();
extern undefined4 FUN_80052778();
extern undefined4 FUN_800528d0();
extern undefined4 FUN_80052904();
extern uint FUN_80053078();
extern undefined8 FUN_80053754();
extern int FUN_8005398c();
extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();
extern undefined4 FUN_800709e8();
extern undefined4 FUN_8011f048();
extern undefined8 FUN_8011f04c();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025cce8();
extern undefined4 FUN_8025da64();
extern undefined4 FUN_8025da88();
extern undefined8 FUN_8028682c();
extern undefined4 FUN_80286878();
extern undefined4 FUN_80294964();

extern undefined4 DAT_8031c130;
extern undefined4 DAT_8031c268;
extern undefined4 DAT_803a9450;
extern undefined4 DAT_803a9684;
extern undefined1 DAT_803a9898;
extern undefined4 DAT_803a98d8;
extern undefined4 DAT_803a9918;
extern undefined4 DAT_803a9958;
extern short DAT_803a9998;
extern short DAT_803a9a18;
extern undefined4 DAT_803a9a98;
extern undefined4 DAT_803a9b98;
extern int DAT_803a9c98;
extern short DAT_803a9d98;
extern int DAT_803a9e18;
extern undefined4 DAT_803a9ff8;
extern undefined4 DAT_803aa008;
extern undefined4 DAT_803aa024;
extern undefined4* DAT_803aa040;
extern undefined4* DAT_803aa044;
extern undefined4* DAT_803aa048;
extern undefined4* DAT_803aa04c;
extern undefined4* DAT_803aa050;
extern undefined4* DAT_803aa054;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc698;
extern undefined4 DAT_803dc6cd;
extern undefined4 DAT_803dc6ce;
extern undefined4* DAT_803dd6d0;
extern undefined4 DAT_803dd970;
extern undefined4 DAT_803de3b8;
extern undefined4 DAT_803de3bc;
extern undefined4 DAT_803de400;
extern undefined4 DAT_803de40e;
extern undefined4 DAT_803de415;
extern undefined4 DAT_803de416;
extern undefined4 DAT_803de418;
extern undefined4 DAT_803de41a;
extern undefined4 DAT_803de41c;
extern undefined4 DAT_803de41e;
extern undefined4 DAT_803de454;
extern undefined4 DAT_803de460;
extern undefined4 DAT_803de4b0;
extern undefined4 DAT_803de4b4;
extern undefined4 DAT_803de4f4;
extern undefined4 DAT_803de504;
extern undefined4 DAT_803de50a;
extern undefined4 DAT_803de514;
extern undefined4 DAT_803de516;
extern undefined4 DAT_803de536;
extern undefined4 DAT_803de537;
extern undefined4 DAT_803de554;
extern undefined4 DAT_803de556;
extern undefined4 DAT_803e2a90;
extern undefined4 DAT_803e2a94;
extern f64 DOUBLE_803e2af8;
extern f64 DOUBLE_803e2b08;
extern f64 DOUBLE_803e2ca8;
extern f64 DOUBLE_803e2cb0;
extern f32 FLOAT_803dc70c;
extern f32 FLOAT_803dc72c;
extern f32 FLOAT_803dc730;
extern f32 FLOAT_803e2abc;
extern f32 FLOAT_803e2ac0;
extern f32 FLOAT_803e2ae8;
extern f32 FLOAT_803e2b44;
extern f32 FLOAT_803e2bb4;
extern f32 FLOAT_803e2c90;
extern f32 FLOAT_803e2c98;
extern f32 FLOAT_803e2c9c;
extern f32 FLOAT_803e2ca0;
extern f32 FLOAT_803e2ca4;
extern f32 FLOAT_803e2cb8;
extern f32 FLOAT_803e2cbc;

/*
 * --INFO--
 *
 * Function: cMenuSetItems
 * EN v1.0 Address: 0x801242DC
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x8012434C
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 lbl_803A87F0[];
extern s16 lbl_8031B4E0[];
extern s16 lbl_803DD894;
extern s8 lbl_803DD896;
extern u16 yButtonState;
extern u16 yButtonItem;
extern s16 yButtonItemTextureId;
extern int gTrickyHudItemMask;
extern int gTrickyHudActionMask;
extern int getTrickyObject(void);
extern int getLoadedFileFlags(int flags);
extern void textureFree();
extern void *textureLoadAsset(int idx);

#pragma peephole off
#pragma scheduling off
int cMenuSetItems(s16 *itemsIn, char useTricky)
{
    int count;
    u8 *base;
    s16 *ids;
    u8 *flP;
    int *wordP;
    s16 *stP;
    s16 *dst;
    s16 *items;
    int halfOff;
    int wordOff;
    s16 *src;
    int active;
    int i;
    s16 *w1;
    s16 *w2;
    s16 *w3;
    u8 *w4;
    s16 *idsW2;
    void **texW;
    void **texP2;
    s16 saved[64];

    items = itemsIn;
    base = lbl_803A87F0;
    ids = (s16 *)(base + 0x948);
    w1 = ids;
    dst = saved;
    w2 = dst;
    stP = (s16 *)(base + 0x548);
    w3 = stP;
    flP = base + 0x448;
    w4 = flP;
    for (i = 0; i < 64; i++) {
        *w2 = *w1;
        *w1 = -1;
        halfOff = 0;
        *w3 = halfOff;
        *w4 = 1;
        w1++;
        w2++;
        w3++;
        w4++;
    }
    count = 0;
    wordOff = 0;
    wordP = (int *)(base + 0x848);
    *wordP = -1;
    if (useTricky == 0) {
        lbl_803DD894 = -1;
        for (src = items; *src > -1; src += 8) {
            active = GameBit_Get(*src);
            if (active != 0) {
                if (items == lbl_8031B4E0) {
                    if (src[1] < 0 || GameBit_Get(src[1]) == 0) {
                        *(s16 *)(base + halfOff + 0x948) = src[3];
                        *(int *)(base + wordOff + 0x848) = src[0];
                        *(int *)(base + wordOff + 0x748) = src[2];
                        *(int *)(base + wordOff + 0x648) = src[1];
                        *(u8 *)(base + count + 0x448) = active;
                        *(s16 *)(base + halfOff + 0x548) = src[6];
                        *(s16 *)(base + halfOff + 0x5c8) = src[5];
                        *(u8 *)(base + count + 0x508) = *(u8 *)(src + 7);
                        *(u8 *)(base + count + 0x4c8) = ((u8 *)src)[0xf];
                        if (src[2] < 0 || GameBit_Get(src[2]) == 0) {
                            *(u8 *)(base + count + 0x488) = 1;
                        } else {
                            *(u8 *)(base + count + 0x488) = 0;
                        }
                        count++;
                        wordOff += 4;
                        halfOff += 2;
                    }
                } else if (src[1] < 0 || GameBit_Get(src[1]) == 0) {
                    if (lbl_803DD896 != 0 && lbl_803DD896 == *src) {
                        lbl_803DD894 = count;
                    }
                    *(s16 *)(base + halfOff + 0x948) = src[3];
                    *(int *)(base + wordOff + 0x848) = src[0];
                    *(int *)(base + wordOff + 0x748) = src[2];
                    *(int *)(base + wordOff + 0x648) = src[1];
                    *(u8 *)(base + count + 0x448) = active;
                    *(s16 *)(base + halfOff + 0x548) = src[6];
                    *(s16 *)(base + halfOff + 0x5c8) = src[5];
                    *(u8 *)(base + count + 0x508) = *(u8 *)(src + 7);
                    *(u8 *)(base + count + 0x4c8) = ((u8 *)src)[0xf];
                    if (src[2] < 0 || GameBit_Get(src[2]) == 0) {
                        *(u8 *)(base + count + 0x488) = 1;
                    } else {
                        *(u8 *)(base + count + 0x488) = 0;
                    }
                    count++;
                    wordOff += 4;
                    halfOff += 2;
                }
            }
        }
    } else {
        int itemMask;
        int actionMask;
        int yItem;
        s16 *idsW;
        s16 *aW;
        u8 *cW;
        u8 *dW;
        u8 *eW;

        getTrickyObject();
        itemMask = gTrickyHudItemMask;
        if (itemMask == -1) {
            if (yButtonState == 2) {
                yButtonState = 0;
                yButtonItemTextureId = -1;
            }
        } else {
            idsW = ids;
            aW = (s16 *)(base + 0x5c8);
            cW = base + 0x508;
            dW = base + 0x4c8;
            eW = base + 0x488;
            actionMask = gTrickyHudActionMask;
            yItem = yButtonItem;
            for (src = items; *src > -1; src += 8) {
                if ((actionMask & *src) != 0) {
                    *idsW = src[3];
                    *flP = 1;
                    *wordP = src[2];
                    *stP = src[6];
                    *aW = src[5];
                    *cW = *(u8 *)(src + 7);
                    *dW = ((u8 *)src)[0xf];
                    if ((itemMask & *src) != 0) {
                        *eW = 1;
                    } else {
                        *eW = 0;
                    }
                    idsW++;
                    flP++;
                    wordP++;
                    stP++;
                    aW++;
                    cW++;
                    dW++;
                    eW++;
                    count++;
                } else if (yButtonState == 2 && yItem == src[2]) {
                    yButtonState = 0;
                    yButtonItemTextureId = -1;
                }
            }
        }
    }
    i = 0;
    idsW2 = ids;
    texP2 = (void **)(base + 0x9c8);
    texW = texP2;
    do {
        if (*dst > -1 && *dst != *idsW2 && *texW != 0) {
            textureFree(*texW);
            *texW = 0;
        }
        dst++;
        idsW2++;
        texW++;
        i++;
    } while (i < 0x40);
    if (getLoadedFileFlags(0) == 0) {
        i = 0;
        do {
            if (*ids > -1 && *texP2 == 0) {
                *texP2 = textureLoadAsset(*ids);
            }
            ids++;
            texP2++;
            i++;
        } while (i < 0x40);
    }
    return count;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_801244B0
 * EN v1.0 Address: 0x8012439C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x801244B0
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fn_801244B0(short *param_1,char param_2)
{
  uint uVar1;
  int iVar2;
  short *psVar3;
  
  iVar2 = 0;
  psVar3 = param_1;
  if (param_2 == '\0') {
    for (; -1 < *psVar3; psVar3 = psVar3 + 8) {
      uVar1 = GameBit_Get((int)*psVar3);
      if (uVar1 != 0) {
        if (param_1 == (short *)&DAT_8031c130) {
          if ((psVar3[2] < 0) || (uVar1 = GameBit_Get((int)psVar3[2]), uVar1 == 0)) {
            iVar2 = iVar2 + 1;
          }
        }
        else if (((psVar3[1] < 0) || (uVar1 = GameBit_Get((int)psVar3[1]), uVar1 == 0)) &&
                ((psVar3[2] < 0 || (uVar1 = GameBit_Get((int)psVar3[2]), uVar1 == 0)))) {
          iVar2 = iVar2 + 1;
        }
      }
    }
  }
  else if (0 < (int)DAT_803de3b8) {
    for (; -1 < *param_1; param_1 = param_1 + 8) {
      if ((DAT_803de3b8 != 0xffffffff) && ((DAT_803de3b8 & (int)*param_1) != 0)) {
        iVar2 = iVar2 + 1;
      }
    }
  }
  return iVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_801244a4
 * EN v1.0 Address: 0x801244A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801245C0
 * EN v1.1 Size: 1208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801244a4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: fn_80124A78
 * EN v1.0 Address: 0x801244A8
 * EN v1.0 Size: 200b
 * EN v1.1 Address: 0x80124A78
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 fn_80124A78(int param_1,int *param_2,int param_3)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  
  uVar3 = DAT_803e2a94;
  iVar1 = FUN_8001792c(*param_2,param_3);
  FUN_80052904();
  uVar3 = CONCAT31(uVar3 >> 8,*(undefined *)(param_1 + 0x37));
  uVar2 = FUN_80053078(*(uint *)(iVar1 + 0x24));
  FUN_80051fc4(uVar2,0,0,(char *)&uVar3,0,1);
  FUN_800528d0();
  FUN_8025cce8(1,4,5,5);
  gxSetZMode_(0,7,0);
  gxSetPeControl_ZCompLoc_(0);
  FUN_8025c754(7,0,0,7,0);
  return 1;
}

/*
 * --INFO--
 *
 * Function: fn_80124B38
 * EN v1.0 Address: 0x80124570
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x80124B38
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 fn_80124B38(int param_1,int *param_2,int param_3)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint *puVar4;
  uint *puVar5;
  
  uVar3 = DAT_803e2a90;
  iVar2 = FUN_8001792c(*param_2,param_3);
  iVar2 = *(byte *)(iVar2 + 0x29) - 1;
  FUN_80052904();
  if ((-1 < iVar2) && (iVar2 < 7)) {
    puVar4 = &DAT_803aa024;
    puVar5 = &DAT_803aa008;
    if (puVar4[iVar2] != 0) {
      if (puVar5[iVar2] == 0) {
        iVar1 = (int)(FLOAT_803e2c90 *
                     (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x37)) -
                            DOUBLE_803e2b08));
        uVar3 = CONCAT31(uVar3 >> 8,(undefined)iVar1);
      }
      else {
        uVar3 = CONCAT31(uVar3 >> 8,*(undefined *)(param_1 + 0x37));
      }
      FUN_80051fc4(puVar4[iVar2],0,0,(char *)&uVar3,0,1);
    }
    else {
      FUN_80052778((char *)&uVar3 + 1);
    }
  }
  else {
    FUN_80052778((char *)&uVar3 + 1);
  }
  FUN_800528d0();
  FUN_8025cce8(1,4,5,5);
  gxSetZMode_(0,7,0);
  gxSetPeControl_ZCompLoc_(0);
  FUN_8025c754(7,0,0,7,0);
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_801246cc
 * EN v1.0 Address: 0x801246CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80124C7C
 * EN v1.1 Size: 1000b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801246cc(undefined4 param_1,undefined4 param_2,undefined4 param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801246d0
 * EN v1.0 Address: 0x801246D0
 * EN v1.0 Size: 748b
 * EN v1.1 Address: 0x80125064
 * EN v1.1 Size: 1220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801246d0(void)
{
  short sVar2;
  short sVar3;
  int iVar1;
  short sVar4;
  int iVar5;
  undefined8 local_10;
  
  sVar2 = DAT_803de41a * (ushort)DAT_803dc070 * 1000;
  iVar5 = (int)sVar2;
  if (iVar5 != 0) {
    sVar3 = DAT_803de41c - DAT_803de41e;
    if (0x8000 < sVar3) {
      sVar3 = sVar3 + 1;
    }
    if (sVar3 < -0x8000) {
      sVar3 = sVar3 + -1;
    }
    if (iVar5 < 0) {
      iVar5 = -iVar5;
    }
    iVar1 = (int)sVar3;
    if (iVar1 < 0) {
      iVar1 = -iVar1;
    }
    if (iVar5 < iVar1) {
      DAT_803de41c = DAT_803de41c + sVar2;
    }
    else {
      DAT_803de41c = DAT_803de41e;
      DAT_803de41a = 0;
    }
    sVar2 = DAT_803de41c;
    sVar3 = DAT_803de41c - DAT_803de41e;
    if (0x8000 < sVar3) {
      sVar3 = sVar3 + 1;
    }
    if (sVar3 < -0x8000) {
      sVar3 = sVar3 + -1;
    }
    iVar5 = (int)sVar3;
    if (iVar5 < 0) {
      iVar5 = -iVar5;
    }
    if (iVar5 < 0x2aab) {
      DAT_803de536 = DAT_803de537;
    }
    *DAT_803aa04c = DAT_803de41c;
    *DAT_803aa040 = sVar2;
    *DAT_803aa050 = sVar2 + 0x5555;
    *DAT_803aa044 = sVar2 + 0x5555;
    *DAT_803aa054 = sVar2 + -0x5556;
    *DAT_803aa048 = sVar2 + -0x5556;
  }
  sVar2 = DAT_803de41c;
  *DAT_803aa04c = DAT_803de41c;
  *DAT_803aa040 = sVar2;
  *DAT_803aa050 = sVar2 + 0x5555;
  *DAT_803aa044 = sVar2 + 0x5555;
  *DAT_803aa054 = sVar2 + -0x5556;
  *DAT_803aa048 = sVar2 + -0x5556;
  sVar2 = DAT_803de41c;
  if (0x8000 < DAT_803de41c) {
    sVar2 = DAT_803de41c + 1;
  }
  if (sVar2 < -0x8000) {
    sVar2 = sVar2 + -1;
  }
  sVar3 = DAT_803de41c + -0x5555;
  if (0x8000 < sVar3) {
    sVar3 = DAT_803de41c + -0x5554;
  }
  if (sVar3 < -0x8000) {
    sVar3 = sVar3 + -1;
  }
  sVar4 = DAT_803de41c + 0x5556;
  if (0x8000 < sVar4) {
    sVar4 = DAT_803de41c + 0x5557;
  }
  if (sVar4 < -0x8000) {
    sVar4 = sVar4 + -1;
  }
  iVar5 = (int)sVar3;
  if (iVar5 < 0) {
    iVar5 = -iVar5;
  }
  iVar1 = (int)sVar2;
  if (iVar1 < 0) {
    iVar1 = -iVar1;
  }
  if (iVar1 < iVar5) {
    sVar3 = sVar2;
    if (sVar2 < 0) {
      sVar3 = -sVar2;
    }
  }
  else if (sVar3 < 0) {
    sVar3 = -sVar3;
  }
  iVar5 = (int)sVar4;
  if (iVar5 < 0) {
    iVar5 = -iVar5;
  }
  if ((iVar5 <= sVar3) && (sVar3 = sVar4, sVar4 < 0)) {
    sVar3 = -sVar4;
  }
  local_10 = (double)CONCAT44(0x43300000,(int)sVar3 ^ 0x80000000);
  sVar2 = (short)(int)-(DOUBLE_803e2cb0 * (local_10 - DOUBLE_803e2af8) - DOUBLE_803e2ca8);
  if (sVar2 < 1) {
    sVar2 = 0;
  }
  DAT_803de554 = (char)sVar2;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801249bc
 * EN v1.0 Address: 0x801249BC
 * EN v1.0 Size: 704b
 * EN v1.1 Address: 0x80125528
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801249bc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int extraout_r4;
  int extraout_r4_00;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar6;
  int local_18 [3];
  
  iVar1 = FUN_80017a98();
  iVar2 = FUN_80017a90();
  uVar4 = 0x280;
  uVar5 = 0x1e0;
  FUN_8025da88(0,0,0x280,0x1e0);
  uVar6 = FUN_8011f04c(param_9,&DAT_803a9ff8);
  if (iVar2 == 0) {
    DAT_803de3b8 = 0;
    DAT_803de3bc = 0;
  }
  else {
    DAT_803de3b8 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x24))(iVar2);
    uVar6 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x20))(iVar2);
    DAT_803de3bc = (undefined4)((ulonglong)uVar6 >> 0x20);
  }
  FUN_8011f048((int)((ulonglong)uVar6 >> 0x20),(int)uVar6,uVar4,uVar5,in_r7,in_r8,in_r9,in_r10);
  iVar3 = (**(code **)(*DAT_803dd6d0 + 0x10))();
  if ((((iVar3 != 0x44) && ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0)) && (DAT_803de400 == '\0'))
     && ((iVar2 != 0 && (iVar1 = FUN_800176d0(), iVar1 == 0)))) {
    iVar3 = **(int **)(iVar2 + 0x68);
    uVar6 = (**(code **)(iVar3 + 0x48))(iVar2,local_18);
    iVar1 = extraout_r4;
    if ((DAT_803de4b4 != 0) && (iVar1 = (int)DAT_803de4b0, iVar1 != local_18[0])) {
      uVar6 = FUN_80053754();
      DAT_803de4b0 = -1;
      DAT_803de4b4 = 0;
      iVar1 = extraout_r4_00;
    }
    if (((DAT_803de4b4 == 0) && (-1 < local_18[0])) &&
       (*(short *)(&DAT_8031c268 + local_18[0] * 2) != -1)) {
      DAT_803de4b4 = FUN_8005398c(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                  (int)*(short *)(&DAT_8031c268 + local_18[0] * 2),iVar1,iVar3,uVar5
                                  ,in_r7,in_r8,in_r9,in_r10);
    }
    DAT_803de4b0 = (short)local_18[0];
    if (DAT_803de4b4 != 0) {
      FUN_800709e8((double)FLOAT_803e2c98,(double)FLOAT_803e2cb8,DAT_803a9684,0xff,0x100);
      FUN_800709e8((double)FLOAT_803e2c98,(double)FLOAT_803e2cbc,DAT_803de4b4,0xff,0x80);
    }
  }
  return;
}

extern u32 lbl_803E1E14;
extern int ObjModel_GetRenderOp(int model, int p);
extern void resetLotsOfRenderVars(void);
extern void *textureIdxToPtr(int idx);
extern void gxFn_80051fb8(void *a, int b, int c, void *d, int e, int f);
extern void textureFn_800528bc(void);
extern void GXSetBlendMode(int a, int b, int c, int d);
extern void gxSetZMode_(int a, int b, int c);
extern void gxSetPeControl_ZCompLoc_(int a);
extern void GXSetAlphaCompare(int a, int b, int c, int d, int e);

#pragma peephole off
#pragma scheduling off
int modelFn_80124794(int obj, int param2, int param3)
{
    int renderOp;
    u8 cfg[4];
    *(u32 *)cfg = lbl_803E1E14;
    renderOp = ObjModel_GetRenderOp(*(int *)param2, param3);
    resetLotsOfRenderVars();
    cfg[3] = *(u8 *)(obj + 0x37);
    gxFn_80051fb8(textureIdxToPtr(*(int *)(renderOp + 0x24)), 0, 0, cfg, 0, 1);
    textureFn_800528bc();
    GXSetBlendMode(1, 4, 5, 5);
    gxSetZMode_(0, 7, 0);
    gxSetPeControl_ZCompLoc_(0);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

extern void *Obj_GetPlayerObject(void);
extern int getTrickyObject(void);
extern void GXSetScissor(int a, int b, int c, int d);
extern void hudDrawTimedElement(int obj, void *p);
extern void drawViewFinderHud(void);
extern int getHudHiddenFrameCount(void);
extern void textureFree(void);
extern void *textureLoadAsset(int idx);
extern void drawTexture(void *p, f32 a, f32 b, int c, int d);
extern int *gCameraInterface;
extern u8 pauseMenuState;
extern int hudTextures[];
extern u8 lbl_803A9398[];
extern s16 gTrickyHudIconTextureIds[];
extern int gTrickyHudItemMask;
extern int gTrickyHudActionMask;
extern s16 gTrickyHudCachedIconIndex;
extern void *gTrickyHudCachedIconTexture;
extern f32 lbl_803E2018;
extern f32 lbl_803E2038;
extern f32 lbl_803E203C;

#pragma peephole off
#pragma scheduling off
void drawTrickyHudOverlay(int obj)
{
    int player;
    int tricky;
    int local_8;
    player = (int)Obj_GetPlayerObject();
    tricky = getTrickyObject();
    GXSetScissor(0, 0, 0x280, 0x1e0);
    hudDrawTimedElement(obj, lbl_803A9398);
    if ((void *)tricky != 0) {
        gTrickyHudItemMask = (*(int (**)(int))(*(int *)(*(int *)(tricky + 0x68)) + 0x24))(tricky);
        gTrickyHudActionMask = (*(int (**)(int))(*(int *)(*(int *)(tricky + 0x68)) + 0x20))(tricky);
    } else {
        gTrickyHudItemMask = 0;
        gTrickyHudActionMask = 0;
    }
    drawViewFinderHud();
    if ((*(int (**)(void))(*(int *)gCameraInterface + 0x10))() != 0x44 &&
        (*(u16 *)(player + 0xb0) & 0x1000) == 0 &&
        pauseMenuState == 0 &&
        (void *)tricky != 0 &&
        getHudHiddenFrameCount() == 0) {
        (*(int (**)(int, int *))(*(int *)(*(int *)(tricky + 0x68)) + 0x48))(tricky, &local_8);
        if (gTrickyHudCachedIconTexture != 0) {
            if (gTrickyHudCachedIconIndex != local_8) {
                textureFree();
                gTrickyHudCachedIconIndex = -1;
                gTrickyHudCachedIconTexture = 0;
            }
        }
        if (gTrickyHudCachedIconTexture == 0) {
            if (local_8 > -1) {
                if (gTrickyHudIconTextureIds[local_8] != -1) {
                    gTrickyHudCachedIconTexture = textureLoadAsset(gTrickyHudIconTextureIds[local_8]);
                }
            }
        }
        gTrickyHudCachedIconIndex = (s16)local_8;
        if (gTrickyHudCachedIconTexture != 0) {
            drawTexture((void *)hudTextures[0x1d], lbl_803E2018, lbl_803E2038, 0xff, 0x100);
            drawTexture(gTrickyHudCachedIconTexture, lbl_803E2018, lbl_803E203C, 0xff, 0x80);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern u32 lbl_803E1E10;
extern void *lbl_803A93C4[7];
extern int lbl_803A93A8[7];
extern f32 lbl_803E2010;
extern f64 lbl_803E1E88;
extern void gxColorFn_80052764(void *p);

#pragma peephole off
#pragma scheduling off
int cMenuRenderFn_80124854(int obj, int param2, int param3)
{
    int idx;
    void *tex;
    u8 cfg[4];
    *(u32 *)cfg = lbl_803E1E10;
    idx = *(u8 *)(ObjModel_GetRenderOp(*(int *)param2, param3) + 0x29) - 1;
    resetLotsOfRenderVars();
    if (idx >= 0 && idx <= 6 && (tex = lbl_803A93C4[idx]) != 0) {
        if (lbl_803A93A8[idx] != 0) {
            cfg[3] = *(u8 *)(obj + 0x37);
        } else {
            cfg[3] = (int)(lbl_803E2010 * (f32)(u32)*(u8 *)(obj + 0x37));
        }
        gxFn_80051fb8(tex, 0, 0, cfg, 0, 1);
    } else {
        cfg[3] = 0;
        gxColorFn_80052764(cfg);
    }
    textureFn_800528bc();
    GXSetBlendMode(1, 4, 5, 5);
    gxSetZMode_(0, 7, 0);
    gxSetPeControl_ZCompLoc_(0);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

extern int Camera_GetCurrentViewSlot(void);
extern void Camera_SetCurrentViewIndex(int idx);
extern void Camera_SetCurrentViewRotation(int a, int b, int c);
extern void Camera_SetCurrentViewPosition(f32 x, f32 y, f32 z);
extern void Camera_UpdateViewMatrices(void);
extern void Camera_ApplyFullViewport(void);
extern int Camera_IsViewYOffsetEnabled(void);
extern void Camera_DisableViewYOffset(void);
extern void Camera_EnableViewYOffset(void);
extern void Camera_RebuildProjectionMatrix(void);
extern f32 Camera_GetFovY(void);
extern void Camera_SetFovY(f32 fov);
extern int Obj_GetActiveModel(int obj);
extern void objRender(int p1, int p2, int p3, int p4, int obj, int p6);
extern void GXSetViewport(f32 x, f32 y, f32 w, f32 h, f32 nearz, f32 farz);
extern void GXSetScissor(int x, int y, int w, int h);
extern f32 sin(f32 x);
extern u8 cMenuState;
extern u8 framesThisStep;
extern s16 lbl_803DD796;
extern s16 cMenuFadeCounter;
extern s16 lbl_803DD79A;
extern s16 lbl_803DD79C;
extern s16 lbl_803DD79E;
extern s16 lbl_803DBA30;
extern int lbl_803DCCF0;
extern int lbl_803DD7E0;
extern u8 lbl_803DD8B6;
extern u8 lbl_803DD8B7;
extern u8 lbl_803DD8D4;
extern f32 lbl_803DBAA4;
extern f32 lbl_803DBAC4;
extern f32 lbl_803DBAC8;
extern int lbl_803A93E0[3];
extern int lbl_803A93EC[3];
extern f32 lbl_803E1E3C;
extern f32 lbl_803E1E40;
extern f32 lbl_803E1E68;
extern f32 lbl_803E1E94;
extern f32 lbl_803E1EC4;
extern f32 lbl_803E1EC8;
extern f32 lbl_803E1F34;
extern f32 lbl_803E201C;
extern f32 lbl_803E2020;
extern f32 lbl_803E2024;
extern f64 lbl_803E2028;
extern f64 lbl_803E2030;

void hudDrawCMenu(int p1, int p2, int p3) {
    int slot;
    int i;
    int sel;
    int model;
    char used[5];
    f32 vals[4];
    f32 sx;
    f32 sy;
    f32 fov;
    f32 small;

    Camera_GetCurrentViewSlot();
    slot = 0;
    if (cMenuState == 3) {
        slot = 1;
    } else if (cMenuState < 3) {
        if (cMenuState > 1) {
            slot = 0;
        }
    } else if (cMenuState < 5) {
        slot = 2;
    }
    vals[3] = 176.0f;
    *(f32 *)(lbl_803A93E0[slot] + 0x10) =
        lbl_803E1E40 + (f32)(-lbl_803DD796 * (u16)lbl_803DBA30) / lbl_803E201C;
    sy = lbl_803DBAC8;
    sx = lbl_803DBAC4;
    fov = Camera_GetFovY();
    lbl_803DBAA4 = fov;
    Camera_SetFovY(lbl_803E2020);
    Camera_SetCurrentViewIndex(1);
    lbl_803DD7E0 = Camera_IsViewYOffsetEnabled();
    Camera_DisableViewYOffset();
    small = lbl_803E1E3C;
    Camera_SetCurrentViewPosition(small, small, small);
    Camera_SetCurrentViewRotation(0x8000, 0, 0);
    Camera_UpdateViewMatrices();
    Camera_RebuildProjectionMatrix();
    GXSetViewport(sx - lbl_803E1F34, sy - lbl_803E2024, (f32)(u32)*(u16 *)(lbl_803DCCF0 + 4),
                  (f32)(u32)*(u16 *)(lbl_803DCCF0 + 8), lbl_803E1E3C, lbl_803E1E68);
    {
        char *u = used;
        int *objs = lbl_803A93EC;
        f32 *v = vals;
        i = 0;
        do {
            u += 1;
            *u = 0;
            *v = sin(lbl_803E1EC8 * (f32)*(s16 *)*objs / lbl_803E1E94);
            objs += 1;
            v += 1;
            i += 1;
        } while (i < 3);
    }
    i = 0;
    do {
        f32 best = lbl_803E1EC4;
        sel = -1;
        if (used[1] == 0 && vals[0] < best) {
            sel = 0;
            best = vals[0];
        }
        if (used[2] == 0 && vals[1] < best) {
            sel = 1;
            best = vals[1];
        }
        if (used[3] == 0 && vals[2] < best) {
            sel = 2;
            best = vals[2];
        }
        if (sel == -1) break;
        model = Obj_GetActiveModel(lbl_803A93EC[sel]);
        *(u16 *)(model + 0x18) &= ~8;
        *(s8 *)(lbl_803A93EC[sel] + 0x37) = cMenuFadeCounter;
        model = Obj_GetActiveModel(lbl_803A93E0[sel]);
        *(u16 *)(model + 0x18) &= ~8;
        *(s8 *)(lbl_803A93E0[sel] + 0x37) = (s8)(cMenuFadeCounter * lbl_803DD8D4 / 0xff);
        if (best <= lbl_803E1E3C) {
            objRender(p1, p2, p3, 0, lbl_803A93EC[sel], 1);
        } else {
            objRender(p1, p2, p3, 0, lbl_803A93EC[sel], 1);
            GXSetScissor(0, 0x79, 0x280, 0x95);
            objRender(p1, p2, p3, 0, lbl_803A93E0[sel], 1);
            GXSetScissor(0, 0, 0x280, 0x1e0);
        }
        used[sel + 1] = 1;
        i += 1;
    } while (i < 3);
    Camera_SetCurrentViewIndex(0);
    if (lbl_803DD7E0 != 0) {
        Camera_EnableViewYOffset();
    }
    Camera_UpdateViewMatrices();
    Camera_SetFovY(lbl_803DBAA4);
    Camera_RebuildProjectionMatrix();
    Camera_ApplyFullViewport();
}

void cMenuRotateFn_80124d80(void) {
    s16 step;
    int astep;
    int adiff;
    int diff;
    s16 cur;
    int d1;
    int d2;
    int d3;
    int a1;
    int a2;
    int a3;
    s16 r;

    step = lbl_803DD79A * (u16)framesThisStep * 1000;
    astep = step;
    if (astep != 0) {
        diff = (s16)(lbl_803DD79C - lbl_803DD79E);
        if (diff > 0x8000) {
            diff = (s16)(diff + 1);
        }
        if (diff < -0x8000) {
            diff = (s16)(diff + -1);
        }
        if (astep < 0) {
            astep = -astep;
        }
        adiff = diff;
        if (adiff < 0) {
            adiff = -adiff;
        }
        if (astep < adiff) {
            lbl_803DD79C = lbl_803DD79C + step;
        } else {
            lbl_803DD79C = lbl_803DD79E;
            lbl_803DD79A = 0;
        }
        cur = lbl_803DD79C;
        diff = (s16)(lbl_803DD79C - lbl_803DD79E);
        if (diff > 0x8000) {
            diff = (s16)(diff + 1);
        }
        if (diff < -0x8000) {
            diff = (s16)(diff + -1);
        }
        adiff = diff;
        if (adiff < 0) {
            adiff = -adiff;
        }
        if (adiff < 0x2aab) {
            lbl_803DD8B6 = lbl_803DD8B7;
        }
        *(s16 *)lbl_803A93EC[0] = lbl_803DD79C;
        *(s16 *)lbl_803A93E0[0] = cur;
        *(s16 *)lbl_803A93EC[1] = cur + 0x5555;
        *(s16 *)lbl_803A93E0[1] = cur + 0x5555;
        *(s16 *)lbl_803A93EC[2] = cur + -0x5556;
        *(s16 *)lbl_803A93E0[2] = cur + -0x5556;
    }
    cur = lbl_803DD79C;
    *(s16 *)lbl_803A93EC[0] = lbl_803DD79C;
    *(s16 *)lbl_803A93E0[0] = cur;
    *(s16 *)lbl_803A93EC[1] = cur + 0x5555;
    *(s16 *)lbl_803A93E0[1] = cur + 0x5555;
    *(s16 *)lbl_803A93EC[2] = cur + -0x5556;
    *(s16 *)lbl_803A93E0[2] = cur + -0x5556;
    d1 = lbl_803DD79C;
    if (d1 > 0x8000) {
        d1 = (s16)(lbl_803DD79C + 1);
    }
    if (d1 < -0x8000) {
        d1 = (s16)(d1 + -1);
    }
    d2 = (s16)(lbl_803DD79C + -0x5555);
    if (d2 > 0x8000) {
        d2 = (s16)(lbl_803DD79C + -0x5554);
    }
    if (d2 < -0x8000) {
        d2 = (s16)(d2 + -1);
    }
    d3 = (s16)(lbl_803DD79C + 0x5556);
    if (d3 > 0x8000) {
        d3 = (s16)(lbl_803DD79C + 0x5557);
    }
    if (d3 < -0x8000) {
        d3 = (s16)(d3 + -1);
    }
    a2 = d2;
    if (a2 < 0) {
        a2 = -a2;
    }
    a1 = d1;
    if (a1 < 0) {
        a1 = -a1;
    }
    if (a1 < a2) {
        d2 = d1;
        if (d1 < 0) {
            d2 = -d1;
        }
    } else if (d2 < 0) {
        d2 = -d2;
    }
    a3 = d3;
    if (a3 < 0) {
        a3 = -a3;
    }
    if (a3 <= d2 && (d2 = d3, d3 < 0)) {
        d2 = -d3;
    }
    r = (s16)(int)-(lbl_803E2030 * (f64)(f32)d2 - lbl_803E2028);
    if (r < 1) {
        r = 0;
    }
    lbl_803DD8D4 = (s8)r;
}
