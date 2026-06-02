#include "ghidra_import.h"
#include "main/dll/baddie/TumbleweedBush.h"

#define SFXsp_sa_def01 243
#define SFXsp_sa_def02 244

typedef struct TitleMenuItem {
    s16 x;
    s16 y;
    u8 flags;
    u8 kind;
    s8 frameDelay;
    u8 pad7;
    s16 minValue;
    s16 maxValue;
    s16 value;
    union {
        s16 textId;
        struct {
            u16 phraseId;
            u16 windowId;
        } window;
    } extra;
} TitleMenuItem;

typedef struct LinkTextureSlot {
    void* texture;
    s16 assetId;
    u8 width;
    u8 pad7;
} LinkTextureSlot;

typedef struct LinkMenuItem {
    u16 textId;
    u16 boxId;
    s16 field04;
    s16 field06;
    s16 field08;
    s16 x;
    s16 y;
    u8 pad0E[2];
    union {
        int textureAssetId;
        void* texture;
    };
    u16 field14;
    u16 flags;
    u8 pad18[2];
    s8 upLink;
    s8 downLink;
    s8 leftLink;
    s8 rightLink;
    s8 state;
    s8 slots[25];
    s8 timer;
    u8 pad39[3];
} LinkMenuItem;

#define TITLE_MENU_FLAG_ENABLED        0x01
#define TITLE_MENU_FLAG_WRAP           0x02
#define TITLE_MENU_FLAG_MOVED_LEFT     0x04
#define TITLE_MENU_FLAG_MOVED_RIGHT    0x08
#define TITLE_MENU_FLAG_CHANGED        0x10
#define TITLE_MENU_FLAG_A_TOGGLE       0x20
#define TITLE_MENU_FLAG_VOLUME_PREVIEW 0x40
#define TITLE_MENU_FLAG_MUSIC_PREVIEW  0x80

#define LINK_FLAG_DISABLE_NAV_TO 0x1000
#define LINK_FLAG_NO_ACCEPT      0x0020
#define LINK_IS_NAVIGABLE(index) ((lbl_803A9458[(index)].flags & LINK_FLAG_DISABLE_NAV_TO) == 0)

#pragma peephole off
#pragma scheduling off

extern undefined8 FUN_80003494();
extern undefined4 FUN_800067b0();
extern undefined4 FUN_80006818();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined8 FUN_80006b9c();
extern undefined4 FUN_80006ba8();
extern undefined4 FUN_80006bac();
extern undefined4 FUN_80006bb0();
extern undefined4 FUN_80006bb4();
extern undefined4 FUN_80006c6c();
extern undefined4 FUN_80017460();
extern undefined4 FUN_80017480();
extern undefined4 FUN_80017484();
extern undefined4 FUN_8001750c();
extern undefined4 FUN_80017510();
extern uint GameBit_Get(int eventId);
extern int FUN_800176d0();
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern undefined4 FUN_80053754();
extern int FUN_8005398c();
extern undefined4 FUN_800709e8();
extern undefined8 FUN_800723a0();
extern undefined8 FUN_80130434();
extern undefined4 FUN_80130588();
extern undefined4 FUN_8013074c();
extern undefined8 FUN_80286824();
extern undefined2 FUN_8028683c();
extern undefined2 FUN_80286840();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern int getHudHiddenFrameCount(void);
extern void padGetAnalogInput(int pad, s8* x, s8* y);
extern void padClearAnalogInputY(int pad);
extern void padClearAnalogInputX(int pad);
extern u32 getButtonsJustPressed(int pad);
extern void buttonDisable(int pad, int mask);
extern void linkDrawFn_801302c0(void);
extern void linkDrawFn_80130484(void);
extern u8 framesThisStep;
extern u8 linkIsRotated;
extern u8 linkFlag_803dd8f8;
extern s16 linkCount_803dd90e;
extern s8 lbl_803DD910;
extern s8 lbl_803DD911;
extern s8 linkSelected;
extern s8 lbl_803DD913;
extern LinkMenuItem lbl_803A9458[40];

extern undefined4 DAT_8031cdf8;
extern undefined4 DAT_8031ce04;
extern short DAT_8031cef8;
extern undefined2 DAT_803aa0b8;
extern undefined4 DAT_803aa0bc;
extern undefined4 DAT_803aa0c2;
extern undefined4 DAT_803aa0cc;
extern undefined4 DAT_803aa0ce;
extern undefined4 DAT_803aa0d2;
extern undefined4 DAT_803aa0d3;
extern undefined4 DAT_803aa0d4;
extern undefined4 DAT_803aa0d5;
extern undefined4 DAT_803aa0d6;
extern int DAT_803aaa18;
extern undefined4 DAT_803aaa1c;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803de578;
extern undefined4 DAT_803de579;
extern undefined4 DAT_803de57a;
extern undefined4 DAT_803de57c;
extern undefined4 DAT_803de57e;
extern undefined4 DAT_803de580;
extern undefined4 DAT_803de582;
extern undefined4 DAT_803de584;
extern undefined4* DAT_803de588;
extern undefined4 DAT_803de58c;
extern undefined4 DAT_803de58e;
extern undefined4 DAT_803de590;
extern undefined4 DAT_803de591;
extern undefined4 DAT_803de592;
extern undefined4 DAT_803de593;
extern undefined4 DAT_803de598;
extern undefined4 DAT_803de5a0;
extern f64 DOUBLE_803e2e78;
extern f32 FLOAT_803de59c;
extern f32 FLOAT_803e2e80;
extern f32 FLOAT_803e2e84;
extern f32 FLOAT_803e2e88;

/*
 * --INFO--
 *
 * Function: Link_update
 * EN v1.0 Address: 0x80130CF0
 * EN v1.0 Size: 936b
 * EN v1.1 Address: 0x80131078
 * EN v1.1 Size: 1168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 Link_update(void)
{
    LinkMenuItem* item;
    int result;
    u32 buttons;
    s8 horizontalInput;
    s8 verticalInput;

    item = &lbl_803A9458[(s8)linkSelected];
    if ((s8)lbl_803DD911 == 0) {
        return -1;
    }

    result = -1;
    if (getHudHiddenFrameCount() != 0) {
        return -1;
    }

    padGetAnalogInput(0, &horizontalInput, &verticalInput);
    if (linkIsRotated != 0) {
        s8 oldHorizontal = horizontalInput;
        horizontalInput = verticalInput;
        verticalInput = (s8)-oldHorizontal;
    }

    if (verticalInput != 0) {
        horizontalInput = 0;
    }

    if (((horizontalInput != 0) || (verticalInput != 0)) && (linkFlag_803dd8f8 != 0)) {
        if ((verticalInput < 0) && (item->downLink != -1) && LINK_IS_NAVIGABLE(item->downLink)) {
            padClearAnalogInputY(0);
            linkSelected = item->downLink;
            linkCount_803dd90e = 0xff;
        } else if ((verticalInput > 0) && (item->upLink != -1) &&
                   LINK_IS_NAVIGABLE(item->upLink)) {
            padClearAnalogInputY(0);
            linkSelected = item->upLink;
            linkCount_803dd90e = 0xff;
        }

        if (item->state != -1) {
            item = &lbl_803A9458[item->state];
            if ((horizontalInput < 0) && (item->leftLink != -1)) {
                padClearAnalogInputX(0);
                lbl_803A9458[(s8)linkSelected].state = item->leftLink;
                linkCount_803dd90e = 0xff;
            } else if ((horizontalInput > 0) && (item->rightLink != -1)) {
                padClearAnalogInputX(0);
                lbl_803A9458[(s8)linkSelected].state = item->rightLink;
                linkCount_803dd90e = 0xff;
            }
        } else {
            if ((horizontalInput < 0) && (item->leftLink != -1) &&
                LINK_IS_NAVIGABLE(item->leftLink)) {
                padClearAnalogInputX(0);
                linkSelected = item->leftLink;
                linkCount_803dd90e = 0xff;
            } else if ((horizontalInput > 0) && (item->rightLink != -1) &&
                       LINK_IS_NAVIGABLE(item->rightLink)) {
                padClearAnalogInputX(0);
                linkSelected = item->rightLink;
                linkCount_803dd90e = 0xff;
            }
        }

        if ((s8)linkSelected < 0) {
            linkSelected = (s8)((s8)lbl_803DD911 - 1);
        }
        if ((s8)linkSelected >= (s8)lbl_803DD911) {
            linkSelected = 0;
        }
    }

    if (lbl_803DD913 != 0) {
        buttons = getButtonsJustPressed(0);
        if ((buttons & 0x1100) != 0) {
            if (((lbl_803A9458[(s8)linkSelected].flags & LINK_FLAG_NO_ACCEPT) == 0) &&
                (GameBit_Get(0x44f) == 0)) {
                buttonDisable(0, 0x1100);
                result = 1;
            }
        } else if ((buttons & 0x200) != 0) {
            buttonDisable(0, 0x200);
            result = 0;
        }
    }

    if (lbl_803DD910 != 0) {
        linkCount_803dd90e = (s16)(linkCount_803dd90e + framesThisStep * 5);
    } else {
        linkCount_803dd90e = (s16)(linkCount_803dd90e - framesThisStep * 5);
    }

    if (linkCount_803dd90e > 0xff) {
        linkCount_803dd90e = (s16)(0xff - (linkCount_803dd90e - 0xff));
        lbl_803DD910 = (s8)(lbl_803DD910 ^ 1);
    } else if (linkCount_803dd90e < 0) {
        linkCount_803dd90e = (s16)-linkCount_803dd90e;
        lbl_803DD910 = (s8)(lbl_803DD910 ^ 1);
    }

    lbl_803DD913 = 1;
    linkDrawFn_801302c0();
    linkDrawFn_80130484();
    return result;
}

/*
 * --INFO--
 *
 * Function: FUN_80131098
 * EN v1.0 Address: 0x80131098
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80131508
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80131098(void)
{
  int iVar1;
  undefined2 *puVar2;
  
  puVar2 = &DAT_803aa0b8;
  for (iVar1 = 0; iVar1 < DAT_803de591; iVar1 = iVar1 + 1) {
    if (*(int *)(puVar2 + 8) != 0) {
      FUN_80053754();
    }
    puVar2 = puVar2 + 0x1e;
  }
  DAT_803de591 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801310fc
 * EN v1.0 Address: 0x801310FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80131574
 * EN v1.1 Size: 640b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801310fc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined param_11,undefined *param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16,
                 undefined2 param_17,undefined2 param_18,undefined2 param_19,undefined2 param_20)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80131100
 * EN v1.0 Address: 0x80131100
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x801317F4
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80131100(void)
{
  int iVar1;
  
  iVar1 = 0;
  do {
    FUN_80053754();
    iVar1 = iVar1 + 1;
  } while (iVar1 < 6);
  FUN_8001750c(3);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80131140
 * EN v1.0 Address: 0x80131140
 * EN v1.0 Size: 392b
 * EN v1.1 Address: 0x8013184C
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80131140(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  undefined4 extraout_r4;
  int iVar2;
  undefined4 *puVar3;
  undefined8 uVar4;
  
  iVar2 = 0;
  puVar3 = &DAT_8031ce04;
  do {
    uVar1 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int)*(short *)(puVar3 + 1),param_10,param_11,param_12,param_13,param_14,
                         param_15,param_16);
    *puVar3 = uVar1;
    puVar3 = puVar3 + 2;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 6);
  uVar4 = FUN_80006b9c(10);
  DAT_803de58c = 0xff;
  FUN_80017510(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,3,extraout_r4,param_11,
               param_12,param_13,param_14,param_15,param_16);
  DAT_803de579 = 0;
  DAT_803de578 = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801312c8
 * EN v1.0 Address: 0x801312C8
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x80131920
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801312c8(int param_1,int param_2)
{
  if (param_2 == 0) {
    *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) & 0xfe;
  }
  else {
    if ((*(byte *)(param_1 + 4) & 1) == 0) {
      DAT_803de598 = 0;
      FLOAT_803de59c =
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xc) ^ 0x80000000) -
                  DOUBLE_803e2e78);
    }
    *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80131348
 * EN v1.0 Address: 0x80131348
 * EN v1.0 Size: 964b
 * EN v1.1 Address: 0x801319A0
 * EN v1.1 Size: 808b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80131348(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  char cVar2;
  uint uVar3;
  byte *pbVar4;
  int iVar5;
  
  bVar1 = *(byte *)((int)param_9 + 5);
  if (bVar1 == 1) {
    if ((*(byte *)(param_9 + 2) & 1) == 0) {
      if (param_9[6] == 0) {
        iVar5 = 5;
      }
      else {
        iVar5 = 3;
      }
    }
    else if (param_9[6] == 0) {
      iVar5 = 4;
    }
    else {
      iVar5 = 2;
    }
    if ((*(byte *)(param_9 + 2) & 0x20) == 0) {
      uVar3 = param_11 & 0xff;
    }
    else {
      uVar3 = (int)(param_11 & 0xff) >> 1;
    }
    FUN_800709e8((double)(float)((double)CONCAT44(0x43300000,(int)*param_9 ^ 0x80000000) -
                                DOUBLE_803e2e78),
                 (double)(float)((double)CONCAT44(0x43300000,(int)param_9[1] ^ 0x80000000) -
                                DOUBLE_803e2e78),(&DAT_803aaa18)[iVar5],uVar3,0x100);
  }
  else if (bVar1 == 0) {
    FUN_800709e8((double)(float)((double)CONCAT44(0x43300000,(int)*param_9 ^ 0x80000000) -
                                DOUBLE_803e2e78),
                 (double)(float)((double)CONCAT44(0x43300000,(int)param_9[1] ^ 0x80000000) -
                                DOUBLE_803e2e78),DAT_803aaa1c,(int)((param_11 & 0xff) * 0xb4) >> 8,
                 0x100);
    FUN_800709e8((double)(float)((double)CONCAT44(0x43300000,
                                                  (int)(((float)((double)CONCAT44(0x43300000,
                                                                                  (int)param_9[7] ^
                                                                                  0x80000000) -
                                                                DOUBLE_803e2e78) *
                                                         ((float)((double)CONCAT44(0x43300000,
                                                                                   (int)param_9[6] -
                                                                                   (int)param_9[4] ^
                                                                                   0x80000000) -
                                                                 DOUBLE_803e2e78) /
                                                         (float)((double)CONCAT44(0x43300000,
                                                                                  (int)param_9[5] -
                                                                                  (int)param_9[4] ^
                                                                                  0x80000000) -
                                                                DOUBLE_803e2e78)) +
                                                        (float)((double)CONCAT44(0x43300000,
                                                                                 (int)*param_9 ^
                                                                                 0x80000000) -
                                                               DOUBLE_803e2e78)) -
                                                       (float)((double)CONCAT44(0x43300000,
                                                                                (int)(uint)*(ushort 
                                                  *)(DAT_803aaa18 + 10) >> 1 ^ 0x80000000) -
                                                  DOUBLE_803e2e78)) ^ 0x80000000) - DOUBLE_803e2e78)
                 ,(double)(float)((double)CONCAT44(0x43300000,(int)param_9[1] - 4U ^ 0x80000000) -
                                 DOUBLE_803e2e78),DAT_803aaa18,(int)((param_11 & 0xff) * 0xff) >> 8,
                 0x100);
  }
  else if (bVar1 < 3) {
    if ((*(byte *)(param_9 + 2) & 0x80) == 0) {
      iVar5 = (int)param_9[6];
    }
    else {
      iVar5 = 0;
    }
    pbVar4 = (byte *)FUN_80017460(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                  (uint)(ushort)param_9[7],iVar5,param_11,param_12,param_13,param_14
                                  ,param_15,param_16);
    FUN_80017484(0,0,0,(byte)((param_11 & 0xff) * 0x96 >> 8));
    FUN_80017480((uint)(ushort)param_9[8],2,2);
    FUN_80006c6c(pbVar4,(uint)(ushort)param_9[8]);
    FUN_80017484(0xff,0xff,0xff,(byte)param_11);
    FUN_80017480((uint)(ushort)param_9[8],0,0);
    FUN_80006c6c(pbVar4,(uint)(ushort)param_9[8]);
  }
  cVar2 = *(char *)(param_9 + 3);
  *(char *)(param_9 + 3) = cVar2 + -1;
  if ((char)(cVar2 + -1) < '\0') {
    *(undefined *)(param_9 + 3) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8013170c
 * EN v1.0 Address: 0x8013170C
 * EN v1.0 Size: 940b
 * EN v1.1 Address: 0x80131CC8
 * EN v1.1 Size: 948b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013170c(int param_1)
{
  byte bVar1;
  short sVar2;
  char cVar4;
  uint uVar3;
  short sVar5;
  short sVar6;
  undefined8 local_20;
  undefined8 local_18;
  
  if ((*(byte *)(param_1 + 4) & 1) == 0) {
    return;
  }
  *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) & 0xe3;
  sVar2 = *(short *)(param_1 + 0xc);
  *(undefined *)(param_1 + 6) = 4;
  bVar1 = *(byte *)(param_1 + 5);
  if (bVar1 != 1) {
    if (bVar1 == 0) {
      cVar4 = FUN_80006bd0(0);
      uVar3 = (uint)cVar4;
      sVar6 = ((short)((int)uVar3 >> 4) + (ushort)((int)uVar3 < 0 && (uVar3 & 0xf) != 0)) * 0xa0;
      if (((sVar6 == 0) ||
          ((FLOAT_803de59c <
            (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 8) ^ 0x80000000) -
                   DOUBLE_803e2e78) && (sVar6 < 0)))) ||
         (((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 10) ^ 0x80000000) -
                  DOUBLE_803e2e78) < FLOAT_803de59c && (0 < sVar6)))) {
        DAT_803de598 = 0;
      }
      else {
        local_20 = (double)CONCAT44(0x43300000,(int)DAT_803de598 ^ 0x80000000);
        DAT_803de598 = (short)(int)(FLOAT_803e2e80 *
                                    (float)((double)CONCAT44(0x43300000,
                                                             (int)(short)(sVar6 - DAT_803de598) ^
                                                             0x80000000) - DOUBLE_803e2e78) +
                                   (float)(local_20 - DOUBLE_803e2e78));
        FUN_800068c4(0,0x3b9);
      }
      local_18 = (double)CONCAT44(0x43300000,(int)DAT_803de598 ^ 0x80000000);
      FLOAT_803de59c = FLOAT_803de59c + (float)(local_18 - DOUBLE_803e2e78) / FLOAT_803e2e84;
      *(short *)(param_1 + 0xc) = (short)(int)(FLOAT_803e2e88 + FLOAT_803de59c);
      if ((*(byte *)(param_1 + 4) & 0x40) != 0) {
        sVar6 = *(short *)(param_1 + 0xc);
        sVar5 = sVar6;
        if (0x7f < sVar6) {
          sVar5 = 0x7f;
        }
        if (sVar5 < 0) {
          sVar6 = 0;
        }
        else if (0x7f < sVar6) {
          sVar6 = 0x7f;
        }
        FUN_80006818((double)FLOAT_803e2e88,0,0x3b9,(byte)sVar6);
      }
      goto LAB_80131fc8;
    }
    if (bVar1 < 3) {
      cVar4 = FUN_80006bd0(0);
      if (cVar4 < '$') {
        if (cVar4 < -0x23) {
          sVar6 = -1;
        }
        else {
          sVar6 = 0;
        }
      }
      else {
        sVar6 = 1;
      }
      sVar5 = sVar6;
      if (DAT_803de5a0 != '\0') {
        sVar5 = 0;
      }
      DAT_803de5a0 = (char)sVar6;
      if (sVar5 < 0) {
        FUN_80006824(0,SFXsp_sa_def01);
        *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + -1;
        *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 4;
      }
      else if (0 < sVar5) {
        FUN_80006824(0,SFXsp_sa_def01);
        *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + 1;
        *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 8;
      }
      goto LAB_80131fc8;
    }
  }
  if (((*(byte *)(param_1 + 4) & 0x20) == 0) && (uVar3 = FUN_80006c00(0), (uVar3 & 0x100) != 0)) {
    FUN_80006824(0,SFXsp_sa_def02);
    *(ushort *)(param_1 + 0xc) = *(ushort *)(param_1 + 0xc) ^ 1;
  }
LAB_80131fc8:
  sVar6 = *(short *)(param_1 + 10);
  if (sVar6 < *(short *)(param_1 + 0xc)) {
    if ((*(byte *)(param_1 + 4) & 2) == 0) {
      *(short *)(param_1 + 0xc) = sVar6;
    }
    else {
      *(undefined2 *)(param_1 + 0xc) = 0;
    }
  }
  else if (*(short *)(param_1 + 0xc) < *(short *)(param_1 + 8)) {
    if ((*(byte *)(param_1 + 4) & 2) == 0) {
      *(short *)(param_1 + 0xc) = *(short *)(param_1 + 8);
    }
    else {
      *(short *)(param_1 + 0xc) = sVar6;
    }
  }
  if (sVar2 != *(short *)(param_1 + 0xc)) {
    *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 0x10;
  }
  if (((*(byte *)(param_1 + 4) & 0x80) != 0) && ((*(byte *)(param_1 + 4) & 0x10) != 0)) {
    FUN_800067b0((int)*(short *)(param_1 + 0xc));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80131ab8
 * EN v1.0 Address: 0x80131AB8
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8013207C
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80131ab8(uint param_1)
{
  FUN_80017814(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80131ad8
 * EN v1.0 Address: 0x80131AD8
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x8013209C
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80131ad8(undefined4 param_1,undefined4 param_2,short param_3,short param_4,short param_5)
{
  undefined2 uVar2;
  int iVar1;
  undefined2 extraout_r4;
  
  uVar2 = FUN_80286840();
  if (param_5 < param_3) {
    param_5 = param_3;
  }
  if (param_4 < param_5) {
    param_5 = param_4;
  }
  iVar1 = FUN_80017830(0x12,5);
  *(undefined *)(iVar1 + 5) = 2;
  *(undefined2 *)(iVar1 + 0xe) = uVar2;
  *(undefined2 *)(iVar1 + 0x10) = extraout_r4;
  *(short *)(iVar1 + 0xc) = param_5;
  *(short *)(iVar1 + 8) = param_3;
  *(short *)(iVar1 + 10) = param_4;
  *(undefined *)(iVar1 + 4) = 2;
  *(undefined *)(iVar1 + 6) = 4;
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80131b78
 * EN v1.0 Address: 0x80131B78
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x80132144
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80131b78(undefined4 param_1,undefined4 param_2,short param_3,short param_4,short param_5)
{
  undefined2 uVar2;
  undefined2 *puVar1;
  undefined2 extraout_r4;
  
  uVar2 = FUN_80286840();
  if (param_5 < param_3) {
    param_5 = param_3;
  }
  if (param_4 < param_5) {
    param_5 = param_4;
  }
  puVar1 = (undefined2 *)FUN_80017830(0xe,5);
  *(undefined *)((int)puVar1 + 5) = 1;
  puVar1[6] = param_5;
  puVar1[4] = param_3;
  puVar1[5] = param_4;
  *puVar1 = uVar2;
  puVar1[1] = extraout_r4;
  *(undefined *)(puVar1 + 2) = 0;
  *(undefined *)(puVar1 + 3) = 4;
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80131c1c
 * EN v1.0 Address: 0x80131C1C
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x801321E8
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80131c1c(undefined4 param_1,undefined4 param_2,short param_3,short param_4,short param_5,
                 undefined2 param_6)
{
  undefined2 uVar2;
  undefined2 *puVar1;
  undefined2 extraout_r4;
  
  uVar2 = FUN_8028683c();
  if (param_5 < param_3) {
    param_5 = param_3;
  }
  if (param_4 < param_5) {
    param_5 = param_4;
  }
  puVar1 = (undefined2 *)FUN_80017830(0x10,5);
  *(undefined *)((int)puVar1 + 5) = 0;
  puVar1[6] = param_5;
  puVar1[4] = param_3;
  puVar1[5] = param_4;
  *puVar1 = uVar2;
  puVar1[1] = extraout_r4;
  *(undefined *)(puVar1 + 2) = 0;
  *(undefined *)(puVar1 + 3) = 4;
  puVar1[7] = param_6;
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80131cc4
 * EN v1.0 Address: 0x80131CC4
 * EN v1.0 Size: 288b
 * EN v1.1 Address: 0x80132294
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80131cc4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  short *psVar3;
  int *piVar4;
  
  iVar2 = 0;
  piVar4 = &DAT_803aaa18;
  psVar3 = &DAT_8031cef8;
  do {
    if (*piVar4 == 0) {
      iVar1 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           (int)*psVar3,param_10,param_11,param_12,param_13,param_14,param_15,
                           param_16);
      *piVar4 = iVar1;
    }
    piVar4 = piVar4 + 1;
    psVar3 = psVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 6);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80131de4
 * EN v1.0 Address: 0x80131DE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80132308
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80131de4(void)
{
}

/* ===== EN v1.0 retargeted leaves ========================================= */

/* EN v1.0 0x80131570  size: 12b  Read changed bit from item->flags. */
int TitleMenuItem_isChanged(TitleMenuItem* item)
{
    return item->flags & TITLE_MENU_FLAG_CHANGED;
}

/* EN v1.0 0x8013157C  size: 20b  Set item->value and item->frameDelay = 2.
 * Logic-only ? target has `extsh r0,r4; sth r0,0xc(r3)` but MWCC -O4
 * strips the redundant extsh before sth (same family as GameUI_func0F /
 * CMenu_SetShouldClose). */
#pragma scheduling off
#pragma peephole off
void TitleMenuItem_setVal(TitleMenuItem* item, int val)
{
    item->value = (s16)val;
    item->frameDelay = 2;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80131590  size: 8b   Getter for item->value. */
s16 TitleMenuItem_getVal(TitleMenuItem* item)
{
    return item->value;
}

extern s16 lbl_803DD918;
extern f32 lbl_803DD91C;
extern s8 lbl_803DD920;
extern u8 lbl_803A9DB8[0x18];
extern f32 lbl_803E21F0;
extern f32 lbl_803E21F4;
extern f32 lbl_803E21F8;
extern s8 padGetStickX(int port);
extern u32 getButtonsJustPressed(int port);
extern void Sfx_PlayFromObject(u32 obj, u32 sfxId);
extern void Sfx_KeepAliveLoopedObjectSound(u32 obj, u32 sfxId);
extern void Sfx_SetObjectSfxVolume(f32 volumeScale, u32 obj, u32 sfxId, u8 volume);
extern void Music_PlayTrackByIndex(int index);
extern void drawTexture(void* texture, u8 alpha, f32 x, f32 y, u16 scale);
extern void* gameTextGetPhrase(int textId, int variant);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextSetWindowStrPos(int windowId, int x, int y);
extern void gameTextAppendStr(void* str, int windowId);

/* EN v1.0 0x80131598  size: 116b  Toggle enabled bit on item->flags. */
#pragma scheduling off
#pragma peephole off
void TitleMenuItem_setEnabled(TitleMenuItem* item, int flag)
{
    if (flag != 0) {
        if ((item->flags & TITLE_MENU_FLAG_ENABLED) == 0) {
            lbl_803DD918 = 0;
            lbl_803DD91C = (f32)item->value;
        }
        item->flags = (u8)(item->flags | TITLE_MENU_FLAG_ENABLED);
    } else {
        item->flags = (u8)(item->flags & ~TITLE_MENU_FLAG_ENABLED);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x8013160C  size: 12b  Read enabled bit from item->flags. */
int TitleMenuItem_isEnabled(TitleMenuItem* item)
{
    return item->flags & TITLE_MENU_FLAG_ENABLED;
}

/* EN v1.0 0x80131618  size: 808b  Render title menu item. */
void TitleMenuItem_render(TitleMenuItem* item, int unused, int alpha)
{
    void* texture;
    void* phrase;
    int textureIndex;
    int drawAlpha;
    int alpha8;
    f32 markerX;

    alpha8 = (u8)alpha;

    if (item->kind == 0) {
        drawTexture(((void**)lbl_803A9DB8)[1], (u8)((alpha8 * 0xb4) >> 8),
                    (f32)item->x, (f32)item->y, 0x100);

        texture = ((void**)lbl_803A9DB8)[0];
        markerX = (f32)(int)((f32)item->extra.textId *
                             ((f32)(item->value - item->minValue) /
                              (f32)(item->maxValue - item->minValue)) +
                             (f32)item->x - (f32)(*(u16*)((u8*)texture + 0xa) >> 1));
        drawTexture(texture, (u8)((alpha8 * 0xff) >> 8),
                    markerX, (f32)(item->y - 4), 0x100);
    } else if (item->kind == 1) {
        if ((item->flags & TITLE_MENU_FLAG_ENABLED) != 0) {
            if (item->value != 0) {
                textureIndex = 2;
            } else {
                textureIndex = 4;
            }
        } else if (item->value != 0) {
            textureIndex = 3;
        } else {
            textureIndex = 5;
        }

        drawAlpha = alpha8;
        if ((item->flags & TITLE_MENU_FLAG_A_TOGGLE) != 0) {
            drawAlpha >>= 1;
        }
        drawTexture(((void**)lbl_803A9DB8)[textureIndex], (u8)drawAlpha,
                    (f32)item->x, (f32)item->y, 0x100);
    } else if (item->kind < 3) {
        if ((item->flags & TITLE_MENU_FLAG_MUSIC_PREVIEW) != 0) {
            phrase = gameTextGetPhrase(item->extra.window.phraseId, 0);
        } else {
            phrase = gameTextGetPhrase(item->extra.window.phraseId, item->value);
        }
        gameTextSetColor(0, 0, 0, (u8)((alpha8 * 0x96) >> 8));
        gameTextSetWindowStrPos(item->extra.window.windowId, 2, 2);
        gameTextAppendStr(phrase, item->extra.window.windowId);
        gameTextSetColor(0xff, 0xff, 0xff, alpha8);
        gameTextSetWindowStrPos(item->extra.window.windowId, 0, 0);
        gameTextAppendStr(phrase, item->extra.window.windowId);
    }

    item->frameDelay--;
    if (item->frameDelay < 0) {
        item->frameDelay = 0;
    }
}

/* EN v1.0 0x80131940  size: 948b  Update title menu item input state. */
void TitleMenuItem_update(TitleMenuItem* item)
{
    s16 oldValue;
    s8 stickX;
    s16 move;
    s16 gatedMove;
    s16 sliderDelta;
    s16 previewVolume;

    if ((item->flags & TITLE_MENU_FLAG_ENABLED) == 0) {
        return;
    }

    item->flags = (u8)(item->flags & 0xe3);
    oldValue = item->value;
    item->frameDelay = 4;

    if (item->kind == 0) {
        stickX = padGetStickX(0);
        sliderDelta = (s16)((s8)stickX / 16) * 0xa0;

        if ((sliderDelta == 0) ||
            ((lbl_803DD91C < (f32)item->minValue) && (sliderDelta < 0)) ||
            (((f32)item->maxValue < lbl_803DD91C) && (sliderDelta > 0))) {
            lbl_803DD918 = 0;
        } else {
            lbl_803DD918 = (s16)(lbl_803E21F0 * (f32)(s16)(sliderDelta - lbl_803DD918) +
                                 (f32)lbl_803DD918);
            Sfx_KeepAliveLoopedObjectSound(0, 0x3b9);
        }

        lbl_803DD91C += (f32)lbl_803DD918 / lbl_803E21F4;
        item->value = (s16)(lbl_803E21F8 + lbl_803DD91C);

        if ((item->flags & TITLE_MENU_FLAG_VOLUME_PREVIEW) != 0) {
            previewVolume = item->value;
            if (previewVolume > 0x7f) {
                previewVolume = 0x7f;
            }
            if (previewVolume < 0) {
                previewVolume = 0;
            } else if (previewVolume > 0x7f) {
                previewVolume = 0x7f;
            }
            Sfx_SetObjectSfxVolume(lbl_803E21F8, 0, 0x3b9, (u8)previewVolume);
        }
    } else if (item->kind >= 2 && item->kind < 3) {
        stickX = padGetStickX(0);
        if (stickX > 0x23) {
            move = 1;
        } else if (stickX < -0x23) {
            move = -1;
        } else {
            move = 0;
        }

        gatedMove = move;
        if (lbl_803DD920 != 0) {
            gatedMove = 0;
        }
        lbl_803DD920 = (s8)move;

        if (gatedMove < 0) {
            Sfx_PlayFromObject(0, SFXsp_sa_def01);
            item->value--;
            item->flags = (u8)(item->flags | TITLE_MENU_FLAG_MOVED_LEFT);
        } else if (gatedMove > 0) {
            Sfx_PlayFromObject(0, SFXsp_sa_def01);
            item->value++;
            item->flags = (u8)(item->flags | TITLE_MENU_FLAG_MOVED_RIGHT);
        }
    } else if (((item->flags & TITLE_MENU_FLAG_A_TOGGLE) == 0) &&
               ((getButtonsJustPressed(0) & 0x100) != 0)) {
        Sfx_PlayFromObject(0, SFXsp_sa_def02);
        item->value = (s16)(item->value ^ 1);
    }

    if (item->value > item->maxValue) {
        if ((item->flags & TITLE_MENU_FLAG_WRAP) == 0) {
            item->value = item->maxValue;
        } else {
            item->value = 0;
        }
    } else if (item->value < item->minValue) {
        if ((item->flags & TITLE_MENU_FLAG_WRAP) == 0) {
            item->value = item->minValue;
        } else {
            item->value = item->maxValue;
        }
    }

    if (oldValue != item->value) {
        item->flags = (u8)(item->flags | TITLE_MENU_FLAG_CHANGED);
    }

    if (((item->flags & TITLE_MENU_FLAG_MUSIC_PREVIEW) != 0) &&
        ((item->flags & TITLE_MENU_FLAG_CHANGED) != 0)) {
        Music_PlayTrackByIndex(item->value);
    }
}

/* EN v1.0 0x80132008  size: 8b   Trivial 1-returner. */
int Dummy3E_func05_ret_1(void) { return 1; }

/* EN v1.0 0x80132010  size: 4b   Empty no-op. */
void Dummy3E_func04_nop(void) {}

/* EN v1.0 0x80132014  size: 8b   Trivial 0-returner. */
int Dummy3E_func03_ret_0(void) { return 0; }

/* EN v1.0 0x8013201C  size: 4b   Empty no-op. */
void Dummy3E_release(void) {}

/* EN v1.0 0x80132020  size: 4b   Empty no-op. */
void Dummy3E_initialise(void) {}

extern u8  linkTextures[0x30];
extern s16 lbl_8031C2A8[6];
extern u8  lbl_803A9DB8[0x18];
extern void mm_free(void);
extern void fn_8001BDD4(int);

/* EN v1.0 0x80131540  size: 48b  Toggle A-button bit of item->flags. */
#pragma peephole off
void TitleMenuItem_setAButtonToggle(TitleMenuItem* item, int flag)
{
    if (flag != 0) {
        item->flags = (u8)(item->flags & ~TITLE_MENU_FLAG_A_TOGGLE);
    } else {
        item->flags = (u8)(item->flags | TITLE_MENU_FLAG_A_TOGGLE);
    }
}
#pragma peephole reset

/* EN v1.0 0x80131CF4  size: 32b  Wrapper for mm_free. */
void TitleMenuItem_free(void)
{
    mm_free();
}

/* EN v1.0 0x80131FE0  size: 40b  Zero 6 u32s at lbl_803A9DB8. */
void TitleMenuItem_initialise(void)
{
    u32* slots = (u32*)lbl_803A9DB8;
    slots[0] = 0;
    slots[1] = 0;
    slots[2] = 0;
    slots[3] = 0;
    slots[4] = 0;
    slots[5] = 0;
}

/* Drift-recovery: add new fns with v1.0 names. */
extern void* textureLoadAsset(int id);
extern void textureFree(void* p);
extern void fn_8001BDD4(int a);
extern void fn_8001BE2C(int mode);
extern void* mmAlloc(int size, int heap, int flags);
extern void* memcpy(void* dst, const void* src, int size);
extern void OSReport(const char* fmt, ...);
extern void padFn_80014b18(int value);
extern s16 linkItemOpacity;
extern s16 linkCount_803dd90e;
extern u8 linkIsRotated;
extern u8 linkFlag_803dd8f8;
extern s16 lbl_803DD8FA;
extern s16 lbl_803DD8FC;
extern s16 lbl_803DD8FE;
extern s16 lbl_803DD900;
extern s16 lbl_803DD902;
extern s16 lbl_803DD904;
extern const char* lbl_803DD908;
extern s8 lbl_803DD910;
extern s8 lbl_803DD911;
extern s8 linkSelected;
extern s8 lbl_803DD913;
extern char lbl_8031C1A8[];
extern LinkMenuItem lbl_803A9458[40];
extern void linkInitTextures(LinkMenuItem* item);

#pragma scheduling off
#pragma peephole off

/* EN v1.0 0x80131D14  size: 168b  Create text-window title menu item. */
TitleMenuItem* TitleMenuItem_createWithWindow(int phraseId, int windowId, s16 minValue,
                                              s16 maxValue, s16 value)
{
    TitleMenuItem* item;

    if (value < minValue) {
        value = minValue;
    }
    if (value > maxValue) {
        value = maxValue;
    }

    item = (TitleMenuItem*)mmAlloc(0x12, 5, 0);
    item->kind = 2;
    item->extra.window.phraseId = phraseId;
    item->extra.window.windowId = windowId;
    item->value = value;
    item->minValue = minValue;
    item->maxValue = maxValue;
    item->flags = 2;
    item->frameDelay = 4;
    return item;
}

/* EN v1.0 0x80131DBC  size: 164b  Create simple title menu item. */
TitleMenuItem* TitleMenuItem_create(s16 x, s16 y, s16 minValue, s16 maxValue, s16 value)
{
    TitleMenuItem* item;

    if (value < minValue) {
        value = minValue;
    }
    if (value > maxValue) {
        value = maxValue;
    }

    item = (TitleMenuItem*)mmAlloc(0xe, 5, 0);
    item->kind = 1;
    item->value = value;
    item->minValue = minValue;
    item->maxValue = maxValue;
    item->x = x;
    item->y = y;
    item->flags = 0;
    item->frameDelay = 4;
    return item;
}

/* EN v1.0 0x80131E60  size: 172b  Create text-backed title menu item. */
TitleMenuItem* TitleMenuItem_createWithText(s16 x, s16 y, s16 minValue, s16 maxValue,
                                            s16 value, int textId)
{
    TitleMenuItem* item;

    if (value < minValue) {
        value = minValue;
    }
    if (value > maxValue) {
        value = maxValue;
    }

    item = (TitleMenuItem*)mmAlloc(0x10, 5, 0);
    item->kind = 0;
    item->value = value;
    item->minValue = minValue;
    item->maxValue = maxValue;
    item->x = x;
    item->y = y;
    item->flags = 0;
    item->frameDelay = 4;
    item->extra.textId = textId;
    return item;
}

void fn_80131F0C(void)
{
    u32* p;
    s16* assetIds;
    int i;

    i = 0;
    p = (u32*)lbl_803A9DB8;
    assetIds = (s16*)lbl_8031C2A8;
    for (; i < 6; i++) {
        if (*p == 0) {
            *p = (u32)textureLoadAsset(*assetIds);
        }
        p++;
        assetIds++;
    }
}

void Link_release(void)
{
    u8* p;
    int i;

    i = 0;
    p = linkTextures;
    for (; i < 6; i++) {
        textureFree(*(void**)p);
        p += 8;
    }
    fn_8001BDD4(3);
}

void Link_initialise(void)
{
    LinkTextureSlot* slot;
    int i;

    i = 0;
    slot = (LinkTextureSlot*)linkTextures;
    for (; i < 6; i++) {
        slot->texture = textureLoadAsset(slot->assetId);
        slot++;
    }

    padFn_80014b18(10);
    linkItemOpacity = 0xff;
    fn_8001BE2C(3);
    linkIsRotated = 0;
    linkFlag_803dd8f8 = 1;
}

void Link_setup(LinkMenuItem* items, int count, int selected, const char* defaultMessage,
                int unused1, int unused2, int baseRed, int baseGreen, int baseBlue,
                int selectedRed, int selectedGreen, int selectedBlue)
{
    const char* defaultText;
    LinkMenuItem* src;
    LinkMenuItem* item;
    int linkedIndex;
    int i;

    src = items;
    defaultText = lbl_8031C1A8;
    if (count <= 40) {
        lbl_803DD911 = (s8)count;
        linkCount_803dd90e = 0xff;
        linkSelected = (s8)selected;
        lbl_803DD910 = 0;
        lbl_803DD913 = 0;

        memcpy(lbl_803A9458, items, count * sizeof(LinkMenuItem));

        item = lbl_803A9458;
        for (i = 0; i < count; i++) {
            linkedIndex = item->upLink;
            if ((linkedIndex < -1) || (linkedIndex >= count)) {
                OSReport(defaultText + 0xa4, linkedIndex);
            }

            linkedIndex = item->downLink;
            if ((linkedIndex < -1) || (linkedIndex >= count)) {
                OSReport(defaultText + 0xb8, linkedIndex);
            }

            linkedIndex = item->leftLink;
            if ((linkedIndex < -1) || (linkedIndex >= count)) {
                OSReport(defaultText + 0xd0, linkedIndex);
            }

            linkedIndex = item->rightLink;
            if ((linkedIndex < -1) || (linkedIndex >= count)) {
                OSReport(defaultText + 0xe8, linkedIndex);
            }

            if (src->textureAssetId != -1) {
                item->texture = textureLoadAsset(src->textureAssetId);
            } else {
                item->texture = NULL;
            }

            if ((item->flags & 0x10) != 0) {
                item->field14 = 0;
                item->field08 = 0;
            }

            if ((item->flags & 0x04) != 0) {
                linkInitTextures(item);
            }

            linkedIndex = item->leftLink;
            if ((linkedIndex != -1) && ((item->flags & 0x08) != 0)) {
                LinkMenuItem* linked = &lbl_803A9458[linkedIndex];
                item->x = linked->x + linked->field14;
                item->field04 = linked->field04 + linked->field14;
            }

            if ((item->flags & 0x0400) != 0) {
                item->x -= (s16)(item->field14 >> 1);
                item->field04 = item->x;
            }

            item->timer = 4;
            item++;
            src++;
        }

        lbl_803DD904 = baseRed;
        lbl_803DD902 = baseGreen;
        lbl_803DD900 = baseBlue;
        lbl_803DD8FE = selectedRed;
        lbl_803DD8FC = selectedGreen;
        lbl_803DD8FA = selectedBlue;
        if (defaultMessage != NULL) {
            defaultText = defaultMessage;
        }
        lbl_803DD908 = defaultText;
    }
}

void TitleMenuItem_release(void)
{
    u32* p;
    int i;

    i = 0;
    p = (u32*)lbl_803A9DB8;
    for (; i < 6; i++) {
        textureFree((void*)*p);
        *p = 0;
        p++;
    }
}

void Link_free(void)
{
    LinkMenuItem* item;
    int i;

    i = 0;
    item = lbl_803A9458;
    for (; i < (s8)lbl_803DD911; i++) {
        if (item->texture != NULL) {
            textureFree(item->texture);
        }
        item++;
    }
    lbl_803DD911 = 0;
}

#pragma peephole reset
#pragma scheduling reset
