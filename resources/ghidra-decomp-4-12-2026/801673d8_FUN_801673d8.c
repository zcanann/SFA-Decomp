// Function: FUN_801673d8
// Entry: 801673d8
// Size: 1228 bytes

void FUN_801673d8(void)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  int aiStack_80 [20];
  char local_30;
  undefined4 local_28;
  uint uStack_24;
  
  piVar2 = (int *)FUN_80286840();
  iVar8 = piVar2[0x13];
  iVar7 = piVar2[0x2e];
  piVar6 = *(int **)(iVar7 + 0x40c);
  iVar3 = FUN_8002bac4();
  local_90 = FLOAT_803e3ccc;
  if ((*piVar6 == 0) && (*(undefined *)(piVar6 + 0x24) = 6, *(byte *)((int)piVar6 + 0x92) >> 4 != 0)
     ) {
    iVar4 = FUN_800381d8(piVar2,0x4ad,&local_90);
    *piVar6 = iVar4;
    if (iVar4 != 0) {
      (**(code **)(**(int **)(*piVar6 + 0x68) + 0x20))(*piVar6,piVar6 + 0x12,(int)piVar6 + 0x91);
      *(undefined *)(piVar6 + 0x24) = 5;
    }
    *(byte *)((int)piVar6 + 0x92) =
         ((*(byte *)((int)piVar6 + 0x92) >> 4) - 1) * '\x10' | *(byte *)((int)piVar6 + 0x92) & 0xf;
  }
  if (piVar2[0x3d] == 0) {
    if (piVar2[0x3e] == 0) {
      piVar2[3] = *(int *)(iVar8 + 8);
      piVar2[4] = *(int *)(iVar8 + 0xc);
      piVar2[5] = *(int *)(iVar8 + 0x10);
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar8 + 0x2e),piVar2,0xffffffff);
      piVar2[0x3e] = 1;
    }
    else {
      iVar8 = (**(code **)(*DAT_803dd738 + 0x30))(piVar2,iVar7,0);
      if (iVar8 != 0) {
        if (((*(byte *)((int)piVar6 + 0x92) >> 1 & 1) == 0) &&
           (iVar8 = FUN_80037fe8((int)piVar2,iVar3,FUN_801679fc), iVar8 != 0)) {
          *(byte *)((int)piVar6 + 0x92) = *(byte *)((int)piVar6 + 0x92) & 0xfd | 2;
        }
        FUN_8002fb40((double)(float)piVar6[0x11],(double)FLOAT_803dc074);
        if (*(short *)(iVar7 + 0x402) != 1) {
          uStack_24 = (uint)*(ushort *)(iVar7 + 0x3fe);
          local_28 = 0x43300000;
          iVar8 = (**(code **)(*DAT_803dd738 + 0x48))
                            ((double)(float)((double)CONCAT44(0x43300000,uStack_24) -
                                            DOUBLE_803e3cd8),piVar2,iVar7,0x8000);
          if (iVar8 != 0) {
            (**(code **)(*DAT_803dd738 + 0x28))
                      (piVar2,iVar7,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4),0,0,1,0,0xffffffff)
            ;
            *(int *)(iVar7 + 0x2d0) = iVar8;
            *(undefined *)(iVar7 + 0x349) = 0;
            *(undefined2 *)(iVar7 + 0x402) = 1;
            *(undefined *)(iVar7 + 0x405) = 2;
          }
          if ((*(int *)(iVar7 + 0x2d0) != 0) && (*(short *)(iVar7 + 0x402) == 2)) {
            uStack_24 = (uint)*(ushort *)(iVar7 + 0x3fe);
            local_28 = 0x43300000;
            if (*(float *)(iVar7 + 0x2c0) <=
                (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e3cd8)) {
              *(undefined2 *)(iVar7 + 0x402) = 1;
            }
          }
        }
        iVar8 = *(int *)(iVar7 + 0x2d0);
        if (iVar8 != 0) {
          local_8c = *(float *)(iVar8 + 0x18) - (float)piVar2[6];
          local_88 = *(float *)(iVar8 + 0x1c) - (float)piVar2[7];
          local_84 = *(float *)(iVar8 + 0x20) - (float)piVar2[8];
          dVar9 = FUN_80293900((double)(local_84 * local_84 +
                                       local_8c * local_8c + local_88 * local_88));
          *(float *)(iVar7 + 0x2c0) = (float)dVar9;
        }
        (**(code **)(*DAT_803dd738 + 0x54))
                  (piVar2,iVar7,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4),0,0,0,0);
        cVar1 = *(char *)(iVar7 + 0x354);
        if (('\0' < cVar1) &&
           ((**(code **)(*DAT_803dd738 + 0x50))
                      (piVar2,iVar7,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4),&DAT_80320f38,
                       &DAT_80320fb0,0,&DAT_803ad298), *(char *)(iVar7 + 0x354) < cVar1)) {
          (**(code **)(**(int **)(*(int *)(iVar3 + 200) + 0x68) + 0x50))();
          DAT_803ad2a4 = piVar2[3];
          DAT_803ad2a8 = piVar2[4];
          DAT_803ad2ac = piVar2[5];
          FUN_8009a468(piVar2,&DAT_803ad298,1,(int *)0x0);
        }
        (**(code **)(*DAT_803dd738 + 0x2c))((double)FLOAT_803e3c74,piVar2,iVar7,0xffffffff);
        *(int *)(iVar7 + 0x3e0) = piVar2[0x30];
        piVar2[0x30] = 0;
        (**(code **)(*DAT_803dd70c + 8))
                  ((double)FLOAT_803dc074,(double)FLOAT_803dc074,piVar2,iVar7,&DAT_803ad2b0,
                   &DAT_803de708);
        piVar2[0x30] = *(int *)(iVar7 + 0x3e0);
        if (((*(byte *)((int)piVar6 + 0x92) & 1) == 0) && (*(char *)(piVar6 + 0x24) == '\x06')) {
          iVar3 = FUN_80064248(piVar2 + 0x20,piVar2 + 3,(float *)0x0,aiStack_80,piVar2,0xffffff84,
                               0xffffffff,0xff,0);
          if ((iVar3 != 0) && (local_30 == '\r')) {
            *(byte *)((int)piVar6 + 0x92) = *(byte *)((int)piVar6 + 0x92) & 0xfe | 1;
            uVar5 = FUN_80022264(10,0xf);
            *(short *)((int)piVar6 + 0x8e) = (short)uVar5 * 0x3c;
          }
        }
      }
    }
  }
  FUN_8028688c();
  return;
}

