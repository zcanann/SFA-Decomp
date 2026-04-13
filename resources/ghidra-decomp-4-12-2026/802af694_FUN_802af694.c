// Function: FUN_802af694
// Entry: 802af694
// Size: 1244 bytes

/* WARNING: Removing unreachable block (ram,0x802afb50) */
/* WARNING: Removing unreachable block (ram,0x802af6a4) */

void FUN_802af694(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  short sVar2;
  bool bVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286840();
  iVar5 = (int)((ulonglong)uVar10 >> 0x20);
  iVar8 = (int)uVar10;
  iVar6 = FUN_8002b660(iVar5);
  iVar6 = *(int *)(iVar6 + 0x30);
  if (*(short *)(iVar8 + 0x806) != 3) {
    if (*(char *)(iVar8 + 0x8b4) == '\x01') {
      FUN_8016eb80(DAT_803df0cc,'\0',*(byte *)(iVar8 + 0x3f4) >> 3 & 1);
      *(undefined *)(iVar8 + 0x8b3) = 0;
      if ((*(short *)(iVar8 + 0x806) != 0) && (*(short *)(iVar8 + 0x806) != 0xf)) {
        *(undefined2 *)(iVar8 + 0x806) = 3;
      }
    }
    else if (*(char *)(iVar8 + 0x8b4) == '\x04') {
      FUN_8016eb80(DAT_803df0cc,'\x01',*(byte *)(iVar8 + 0x3f4) >> 3 & 1);
      *(undefined *)(iVar8 + 0x8b3) = 1;
      if ((*(short *)(iVar8 + 0x806) != 0) && (*(short *)(iVar8 + 0x806) != 0xf)) {
        *(undefined2 *)(iVar8 + 0x806) = 3;
      }
    }
  }
  dVar9 = -(double)FLOAT_803e8bb8;
  bVar3 = false;
  do {
    bVar4 = false;
    sVar2 = *(short *)(iVar8 + 0x806);
    if (sVar2 == 3) {
      if ((int)*(short *)(iVar5 + 0xa2) != (int)*(short *)(iVar5 + 0xa0)) {
        FUN_8002f334((double)*(float *)(iVar5 + 0x98),param_2,param_3,param_4,param_5,param_6,
                     param_7,param_8,iVar5,(int)*(short *)(iVar5 + 0xa0),0);
      }
      if (*(short *)(iVar6 + 0x58) == 0) {
        *(undefined2 *)(iVar5 + 0xa2) = 0xffff;
        *(undefined2 *)(iVar8 + 0x806) = 0;
      }
      else {
        param_2 = (double)FLOAT_803dc074;
        FUN_8002eeb8((double)FLOAT_803e8b3c,param_2,iVar5,0);
        FUN_8002f304((double)*(float *)(iVar5 + 0x98),iVar5);
      }
    }
    else if (sVar2 < 3) {
      if (sVar2 == 1) {
        if (bVar3) {
          FUN_8002f334((double)*(float *)(iVar5 + 0x98),param_2,param_3,param_4,param_5,param_6,
                       param_7,param_8,iVar5,(int)*(short *)(iVar5 + 0xa0),0);
          if ((*(int *)(iVar8 + 0x4b8) == 0) ||
             ((sVar2 = *(short *)(*(int *)(iVar8 + 0x4b8) + 0x44), sVar2 != 0x1c && (sVar2 != 0x2a))
             )) {
            FUN_8002f334((double)FLOAT_803e8c00,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,iVar5,0x8d,0);
          }
          else {
            FUN_8002f334((double)FLOAT_803e8c00,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,iVar5,0x82,0);
          }
          FUN_8002f66c(iVar5,0xc);
        }
        if (*(float *)(iVar5 + 0x9c) <= FLOAT_803e8dc8) {
          *(undefined *)(iVar8 + 0x8b3) = 0;
        }
        if (FLOAT_803e8b4c < *(float *)(iVar5 + 0x9c)) {
          param_2 = (double)FLOAT_803e8b78;
          FUN_8002eeb8(dVar9,param_2,iVar5,0);
        }
        else {
          *(undefined2 *)(iVar8 + 0x806) = 3;
          bVar4 = true;
        }
      }
      else {
        if (sVar2 < 1) goto LAB_802afad0;
        if (bVar3) {
          FUN_8002f334((double)*(float *)(iVar5 + 0x98),param_2,param_3,param_4,param_5,param_6,
                       param_7,param_8,iVar5,(int)*(short *)(iVar5 + 0xa0),0);
          if ((*(int *)(iVar8 + 0x4b8) == 0) ||
             ((sVar2 = *(short *)(*(int *)(iVar8 + 0x4b8) + 0x44), sVar2 != 0x1c && (sVar2 != 0x2a))
             )) {
            FUN_8002f334((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,iVar5,0x8d,0);
          }
          else {
            FUN_8002f334((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,iVar5,0x82,0);
          }
          FUN_8002f66c(iVar5,0xc);
        }
        if (FLOAT_803e8dc8 <= *(float *)(iVar5 + 0x9c)) {
          *(undefined *)(iVar8 + 0x8b3) = 1;
        }
        if (*(float *)(iVar5 + 0x9c) < FLOAT_803e8bb4) {
          param_2 = (double)FLOAT_803e8b78;
          FUN_8002eeb8((double)FLOAT_803e8bb8,param_2,iVar5,0);
        }
        else {
          FUN_8016eb80(DAT_803df0cc,'\x01','\0');
          *(undefined2 *)(iVar8 + 0x806) = 3;
          bVar4 = true;
        }
      }
    }
    else if (sVar2 == 0xf) {
      if (bVar3) {
        FUN_8002f334((double)*(float *)(iVar5 + 0x98),param_2,param_3,param_4,param_5,param_6,
                     param_7,param_8,iVar5,(int)*(short *)(iVar5 + 0xa0),0);
        FUN_8002f334((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     iVar5,(int)*(short *)(&DAT_803342cc + (uint)*(byte *)(iVar8 + 0x8a2) * 2),0);
        FUN_8002f66c(iVar5,0xc);
      }
      if (*(float *)(iVar5 + 0x9c) < FLOAT_803e8b78) {
        bVar1 = *(byte *)(iVar8 + 0x3f0);
        if (((((bVar1 >> 4 & 1) == 0) && ((bVar1 >> 2 & 1) == 0)) && ((bVar1 >> 3 & 1) == 0)) &&
           (((bVar1 >> 5 & 1) == 0 && (iVar7 = (int)*(short *)(iVar8 + 0x274), iVar7 != 0x36)))) {
          if ((((iVar7 - 1U & 0xffff) < 2) || ((iVar7 - 0x24U & 0xffff) < 2)) ||
             (*(int *)(iVar8 + 0x2d0) != 0)) {
            bVar3 = true;
          }
          else {
            bVar3 = false;
          }
        }
        else {
          bVar3 = false;
        }
        if (bVar3) {
          param_2 = (double)FLOAT_803dc074;
          FUN_8002eeb8((double)*(float *)(&DAT_803342fc + (uint)*(byte *)(iVar8 + 0x8a2) * 4),
                       param_2,iVar5,0);
          goto LAB_802afb44;
        }
      }
      *(undefined2 *)(iVar8 + 0x806) = 3;
      *(undefined *)(iVar8 + 0x8a2) = 0xff;
      bVar4 = true;
    }
    else {
LAB_802afad0:
      if (*(char *)(iVar8 + 0x8b3) == '\0') {
        if (*(char *)(iVar8 + 0x8b4) == '\x02') {
          *(undefined2 *)(iVar8 + 0x806) = 2;
          bVar4 = true;
        }
      }
      else if (*(char *)(iVar8 + 0x8b4) == '\0') {
        FUN_8016eb80(DAT_803df0cc,'\0','\0');
        *(undefined2 *)(iVar8 + 0x806) = 1;
        bVar4 = true;
      }
      if ((*(char *)(iVar8 + 0x8a2) == '\x05') || (*(char *)(iVar8 + 0x8a2) == '\a')) {
        *(undefined2 *)(iVar8 + 0x806) = 0xf;
        bVar4 = true;
      }
    }
LAB_802afb44:
    bVar3 = bVar4;
    if (!bVar4) {
      FUN_8028688c();
      return;
    }
  } while( true );
}

