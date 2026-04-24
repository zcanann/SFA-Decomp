// Function: FUN_8015add0
// Entry: 8015add0
// Size: 728 bytes

/* WARNING: Removing unreachable block (ram,0x8015b084) */
/* WARNING: Removing unreachable block (ram,0x8015ade0) */

void FUN_8015add0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)

{
  int iVar1;
  uint uVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined *puVar3;
  undefined8 uVar4;
  double dVar5;
  
  puVar3 = (&PTR_DAT_80320998)[(uint)*(ushort *)(param_10 + 0x338) * 2];
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6e) = 10;
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6f) = 1;
  if (param_9[0x50] == 0) {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
    FUN_80035ff8((int)param_9);
  }
  else {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
    FUN_80036018((int)param_9);
  }
  if (((*(uint *)(param_10 + 0x2dc) & 0x80000000) != 0) && (*(byte *)(param_10 + 0x33a) < 2)) {
    if ((*(short *)(param_10 + 0x338) == 0) && (uVar2 = FUN_80022264(0,0x14), 9 < (int)uVar2)) {
      *(undefined *)(param_10 + 0x33a) = 7;
    }
    else {
      *(undefined *)(param_10 + 0x33a) = 1;
    }
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x40000000;
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    *(char *)(param_10 + 0x33a) = *(char *)(param_10 + 0x33a) + '\x01';
    if ((byte)(&DAT_803dc994)[*(ushort *)(param_10 + 0x338)] < *(byte *)(param_10 + 0x33a)) {
      *(undefined *)(param_10 + 0x33a) = (&DAT_803dc990)[*(ushort *)(param_10 + 0x338)];
    }
    if (*(ushort *)(param_10 + 0x2a0) < 4) {
      iVar1 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
      uVar4 = FUN_8014d504((double)*(float *)(puVar3 + iVar1),param_2,param_3,param_4,param_5,
                           param_6,param_7,param_8,(int)param_9,param_10,
                           (uint)(byte)puVar3[iVar1 + 8],0,0,in_r8,in_r9,in_r10);
    }
    else {
      iVar1 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
      uVar4 = FUN_8014d504((double)*(float *)(puVar3 + iVar1),param_2,param_3,param_4,param_5,
                           param_6,param_7,param_8,(int)param_9,param_10,
                           (uint)(byte)puVar3[iVar1 + 9],0,0,in_r8,in_r9,in_r10);
    }
    if (param_9[0x50] == 9) {
      FUN_8015a9d8(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
    else if (param_9[0x50] == 1) {
      uVar2 = FUN_80022264(0,(uint)*(byte *)(param_10 + 0x33b));
      FUN_80022264(0xffff8000,0x7fff);
      dVar5 = (double)FUN_802945e0();
      *(float *)(param_9 + 6) =
           (float)((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3948
                                  ) * dVar5 + (double)*(float *)(*(int *)(param_9 + 0x26) + 8));
      dVar5 = (double)FUN_80294964();
      *(float *)(param_9 + 10) =
           (float)((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3948
                                  ) * dVar5 + (double)*(float *)(*(int *)(param_9 + 0x26) + 0x10));
      FUN_8014d3f4(param_9,param_10,1,0);
    }
  }
  FUN_8014d3f4(param_9,param_10,(uint)(byte)(&DAT_803dc998)[*(ushort *)(param_10 + 0x338)],0);
  FUN_8015ac28((uint)param_9,param_10);
  return;
}

