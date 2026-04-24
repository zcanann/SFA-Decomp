// Function: FUN_80029260
// Entry: 80029260
// Size: 344 bytes

undefined *
FUN_80029260(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            )

{
  int iVar1;
  undefined *puVar2;
  uint uVar3;
  int *piVar4;
  uint *puVar5;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar6;
  int local_28;
  uint local_24;
  undefined4 local_20;
  uint local_1c;
  uint local_18 [3];
  
  iVar1 = FUN_80043680(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x2a,param_9,
                       local_18);
  if (iVar1 == 0) {
    puVar2 = (undefined *)0x0;
  }
  else {
    piVar4 = &local_28;
    puVar5 = &local_1c;
    uVar3 = param_9;
    uVar6 = FUN_80048bd4(local_18[0],&local_20,&local_24,piVar4,puVar5);
    local_24 = FUN_80022f00(local_24);
    local_24 = local_24 + 0xb0;
    uVar3 = FUN_80025894(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         local_28,local_20,piVar4,puVar5,uVar3,in_r9,in_r10);
    iVar1 = local_1c + uVar3 + 500;
    uVar3 = FUN_80023d8c(iVar1,9);
    puVar2 = (undefined *)FUN_80022f18(uVar3);
    FUN_802420b0((uint)puVar2,iVar1);
    FUN_80046644(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x2b,puVar2,
                 local_18[0],local_1c,(uint *)0x0,param_9,0,in_r10);
    *(short *)(puVar2 + 0x84) = (short)local_24;
    *(short *)(puVar2 + 4) = (short)param_9;
    *(undefined2 *)(puVar2 + 0xec) = local_20._2_2_;
    *(ushort *)(puVar2 + 2) = *(ushort *)(puVar2 + 2) & 0xffbf;
    *puVar2 = 1;
    if (*(short *)(puVar2 + 0xec) == 0) {
      *(ushort *)(puVar2 + 2) = *(ushort *)(puVar2 + 2) | 2;
    }
    if (local_28 != 0) {
      *(ushort *)(puVar2 + 2) = *(ushort *)(puVar2 + 2) | 0x40;
    }
  }
  return puVar2;
}

