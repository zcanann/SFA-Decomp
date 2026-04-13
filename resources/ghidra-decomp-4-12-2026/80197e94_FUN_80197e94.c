// Function: FUN_80197e94
// Entry: 80197e94
// Size: 828 bytes

void FUN_80197e94(void)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  uint *puVar7;
  int local_28 [2];
  undefined8 local_20;
  
  iVar1 = FUN_80286840();
  puVar7 = *(uint **)(iVar1 + 0xb8);
  iVar5 = *(int *)(iVar1 + 0x4c);
  uVar2 = (uint)*(short *)(iVar5 + 0x24);
  if (uVar2 != 0xffffffff) {
    if (*(char *)((int)puVar7 + 0x25) < '\0') {
      uVar2 = FUN_80020078(uVar2);
      if (uVar2 == 0) {
        *(byte *)((int)puVar7 + 0x25) = *(byte *)((int)puVar7 + 0x25) & 0x7f;
        if (*puVar7 != 0) {
          FUN_800238c4(*puVar7);
          *puVar7 = 0;
        }
      }
    }
    else {
      uVar2 = FUN_80020078(uVar2);
      if (uVar2 != 0) {
        *(byte *)((int)puVar7 + 0x25) = *(byte *)((int)puVar7 + 0x25) & 0x7f | 0x80;
      }
    }
  }
  if ((*puVar7 == 0) && (*(char *)((int)puVar7 + 0x25) < '\0')) {
    puVar7[6] = (uint)((float)puVar7[6] - FLOAT_803dc074);
    if ((float)puVar7[6] <= FLOAT_803e4d20) {
      local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x23) * 0x3c ^ 0x80000000);
      puVar7[6] = (uint)((float)puVar7[6] + (float)(local_20 - DOUBLE_803e4d30));
      piVar3 = FUN_80037048(0x48,local_28);
      iVar6 = 0;
      piVar4 = piVar3;
      iVar5 = local_28[0];
      if (0 < local_28[0]) {
        do {
          if (*(uint *)(*(int *)(*piVar4 + 0x4c) + 0x14) == puVar7[8]) break;
          piVar4 = piVar4 + 1;
          iVar6 = iVar6 + 1;
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
      }
      if (iVar6 == local_28[0]) {
        *(byte *)((int)puVar7 + 0x25) = *(byte *)((int)puVar7 + 0x25) & 0x7f;
        goto LAB_801981b8;
      }
      uVar2 = FUN_80022264(0xfffffffb,5);
      uVar2 = FUN_8008fdac((double)(float)puVar7[2],(double)(float)puVar7[3],iVar1 + 0xc,
                           piVar3[iVar6] + 0xc,(ushort)*(byte *)(puVar7 + 7) + (short)uVar2,
                           *(undefined *)((int)puVar7 + 0x1d),
                           (*(byte *)((int)puVar7 + 0x25) >> 5 & 1) != 0);
      *puVar7 = uVar2;
      puVar7[1] = (uint)FLOAT_803e4d20;
      if ((*(byte *)(puVar7 + 9) & 1) != 0) {
        FUN_800972fc(iVar1,1,7,0x1e,0);
      }
      iVar5 = *(int *)(piVar3[iVar6] + 0xb8);
      if ((*(byte *)(iVar5 + 0x24) & 1) != 0) {
        FUN_800972fc(piVar3[iVar6],1,7,0x1e,0);
      }
      if ((*(byte *)(puVar7 + 9) & 2) != 0) {
        FUN_80097568((double)(float)puVar7[5],(double)FLOAT_803e4d24,iVar1,5,1,1,100,0,0);
      }
      if ((*(byte *)(iVar5 + 0x24) & 2) != 0) {
        FUN_80097568((double)*(float *)(iVar5 + 0x14),(double)FLOAT_803e4d24,piVar3[iVar6],5,1,1,100
                     ,0,0);
      }
    }
  }
  if (*puVar7 != 0) {
    if ((*(byte *)((int)puVar7 + 0x25) >> 6 & 1) == 0) {
      puVar7[1] = (uint)((float)puVar7[1] + FLOAT_803dc074);
      local_20 = (double)(longlong)(int)(FLOAT_803e4d28 + (float)puVar7[1]);
      *(short *)(*puVar7 + 0x20) = (short)(int)(FLOAT_803e4d28 + (float)puVar7[1]);
    }
    uVar2 = *puVar7;
    if (*(ushort *)(uVar2 + 0x22) <= *(ushort *)(uVar2 + 0x20)) {
      FUN_800238c4(uVar2);
      *puVar7 = 0;
    }
  }
LAB_801981b8:
  FUN_8028688c();
  return;
}

