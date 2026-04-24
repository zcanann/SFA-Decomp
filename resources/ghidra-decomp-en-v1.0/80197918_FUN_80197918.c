// Function: FUN_80197918
// Entry: 80197918
// Size: 828 bytes

void FUN_80197918(void)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  short sVar4;
  int *piVar5;
  int iVar6;
  int *piVar7;
  int local_28 [2];
  double local_20;
  
  iVar1 = FUN_802860dc();
  piVar7 = *(int **)(iVar1 + 0xb8);
  iVar6 = *(int *)(iVar1 + 0x4c);
  if (*(short *)(iVar6 + 0x24) != -1) {
    if (*(char *)((int)piVar7 + 0x25) < '\0') {
      iVar2 = FUN_8001ffb4();
      if ((iVar2 == 0) &&
         (*(byte *)((int)piVar7 + 0x25) = *(byte *)((int)piVar7 + 0x25) & 0x7f, *piVar7 != 0)) {
        FUN_80023800();
        *piVar7 = 0;
      }
    }
    else {
      iVar2 = FUN_8001ffb4();
      if (iVar2 != 0) {
        *(byte *)((int)piVar7 + 0x25) = *(byte *)((int)piVar7 + 0x25) & 0x7f | 0x80;
      }
    }
  }
  if ((*piVar7 == 0) && (*(char *)((int)piVar7 + 0x25) < '\0')) {
    piVar7[6] = (int)((float)piVar7[6] - FLOAT_803db414);
    if ((float)piVar7[6] <= FLOAT_803e4088) {
      local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x23) * 0x3c ^ 0x80000000);
      piVar7[6] = (int)((float)piVar7[6] + (float)(local_20 - DOUBLE_803e4098));
      piVar3 = (int *)FUN_80036f50(0x48,local_28);
      iVar2 = 0;
      piVar5 = piVar3;
      iVar6 = local_28[0];
      if (0 < local_28[0]) {
        do {
          if (*(int *)(*(int *)(*piVar5 + 0x4c) + 0x14) == piVar7[8]) break;
          piVar5 = piVar5 + 1;
          iVar2 = iVar2 + 1;
          iVar6 = iVar6 + -1;
        } while (iVar6 != 0);
      }
      if (iVar2 == local_28[0]) {
        *(byte *)((int)piVar7 + 0x25) = *(byte *)((int)piVar7 + 0x25) & 0x7f;
        goto LAB_80197c3c;
      }
      sVar4 = FUN_800221a0(0xfffffffb,5);
      iVar6 = FUN_8008fb20((double)(float)piVar7[2],(double)(float)piVar7[3],iVar1 + 0xc,
                           piVar3[iVar2] + 0xc,(ushort)*(byte *)(piVar7 + 7) + sVar4,
                           *(undefined *)((int)piVar7 + 0x1d),
                           (*(byte *)((int)piVar7 + 0x25) >> 5 & 1) != 0);
      *piVar7 = iVar6;
      piVar7[1] = (int)FLOAT_803e4088;
      if ((*(byte *)(piVar7 + 9) & 1) != 0) {
        FUN_80097070((double)(float)piVar7[4],iVar1,1,7,0x1e,0);
      }
      iVar6 = *(int *)(piVar3[iVar2] + 0xb8);
      if ((*(byte *)(iVar6 + 0x24) & 1) != 0) {
        FUN_80097070((double)*(float *)(iVar6 + 0x10),piVar3[iVar2],1,7,0x1e,0);
      }
      if ((*(byte *)(piVar7 + 9) & 2) != 0) {
        FUN_800972dc((double)(float)piVar7[5],(double)FLOAT_803e408c,iVar1,5,1,1,100,0,0);
      }
      if ((*(byte *)(iVar6 + 0x24) & 2) != 0) {
        FUN_800972dc((double)*(float *)(iVar6 + 0x14),(double)FLOAT_803e408c,piVar3[iVar2],5,1,1,100
                     ,0,0);
      }
    }
  }
  if (*piVar7 != 0) {
    if ((*(byte *)((int)piVar7 + 0x25) >> 6 & 1) == 0) {
      piVar7[1] = (int)((float)piVar7[1] + FLOAT_803db414);
      local_20 = (double)(longlong)(int)(FLOAT_803e4090 + (float)piVar7[1]);
      *(short *)(*piVar7 + 0x20) = (short)(int)(FLOAT_803e4090 + (float)piVar7[1]);
    }
    if (*(ushort *)(*piVar7 + 0x22) <= *(ushort *)(*piVar7 + 0x20)) {
      FUN_80023800();
      *piVar7 = 0;
    }
  }
LAB_80197c3c:
  FUN_80286128();
  return;
}

