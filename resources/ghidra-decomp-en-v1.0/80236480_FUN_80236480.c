// Function: FUN_80236480
// Entry: 80236480
// Size: 492 bytes

void FUN_80236480(void)

{
  byte bVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  byte *pbVar5;
  byte *pbVar6;
  int iVar7;
  int iVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_802860d0();
  iVar2 = (int)((ulonglong)uVar9 >> 0x20);
  piVar3 = (int *)uVar9;
  iVar8 = *(int *)(iVar2 + 0x4c);
  piVar3[4] = (int)((float)piVar3[4] - FLOAT_803db414);
  if (FLOAT_803e7360 < (float)piVar3[4]) {
    uVar4 = (uint)(byte)(&DAT_803dc3e0)[*(byte *)((int)piVar3 + 0x23)];
  }
  else {
    piVar3[4] = (int)FLOAT_803e7364;
    *(char *)((int)piVar3 + 0x23) = *(char *)((int)piVar3 + 0x23) + '\x01';
    if (2 < *(byte *)((int)piVar3 + 0x23)) {
      *(undefined *)((int)piVar3 + 0x23) = 0;
    }
    uVar4 = (uint)(byte)(&DAT_803dc3e0)[*(byte *)((int)piVar3 + 0x23)];
    if (*piVar3 != 0) {
      iVar7 = uVar4 * 3;
      pbVar5 = &DAT_8032bd51 + iVar7;
      pbVar6 = &DAT_8032bd52 + iVar7;
      FUN_8001daf0(*piVar3,(&DAT_8032bd50)[iVar7],*pbVar5,*pbVar6,0xff);
      FUN_8001da18(*piVar3,(&DAT_8032bd50)[iVar7],*pbVar5,*pbVar6,0xff);
      FUN_8001dab8(*piVar3,(int)(FLOAT_803e7368 *
                                (float)((double)CONCAT44(0x43300000,
                                                         (uint)(byte)(&DAT_8032bd50)[iVar7]) -
                                       DOUBLE_803e7358)),
                   (int)(FLOAT_803e7368 *
                        (float)((double)CONCAT44(0x43300000,(uint)*pbVar5) - DOUBLE_803e7358)),
                   (int)(FLOAT_803e7368 *
                        (float)((double)CONCAT44(0x43300000,(uint)*pbVar6) - DOUBLE_803e7358)),0xff)
      ;
      bVar1 = *(byte *)(iVar8 + 0x29);
      if ((bVar1 & 0x40) != 0) {
        if ((bVar1 & 0x80) == 0) {
          FUN_8001d730((double)(FLOAT_803e7370 * *(float *)(iVar2 + 8)),*piVar3,0,
                       (&DAT_8032bd50)[iVar7],*pbVar5,*pbVar6,0x87);
        }
        else {
          FUN_8001d730((double)(FLOAT_803e736c * *(float *)(iVar2 + 8)),*piVar3,0,
                       (&DAT_8032bd50)[iVar7],*pbVar5,*pbVar6,0x87);
        }
      }
    }
  }
  FUN_8028611c(uVar4);
  return;
}

