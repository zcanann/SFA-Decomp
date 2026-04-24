// Function: FUN_8002919c
// Entry: 8002919c
// Size: 324 bytes

undefined * FUN_8002919c(undefined4 param_1)

{
  int iVar1;
  undefined *puVar2;
  int local_28;
  int local_24;
  undefined4 local_20;
  int local_1c;
  undefined4 local_18 [4];
  
  iVar1 = FUN_80043588(0x2a,param_1,local_18);
  if (iVar1 == 0) {
    puVar2 = (undefined *)0x0;
  }
  else {
    FUN_80048a58(local_18[0],&local_20,&local_24,&local_28,&local_1c,param_1);
    local_24 = FUN_80022e3c(local_24);
    local_24 = local_24 + 0xb0;
    iVar1 = FUN_800257d0(param_1,local_28,local_20);
    FUN_80023cc8(local_1c + iVar1 + 500,9,0);
    puVar2 = (undefined *)FUN_80022e54();
    FUN_800464c8(0x2b,puVar2,local_18[0],local_1c,0,param_1,0);
    *(short *)(puVar2 + 0x84) = (short)local_24;
    *(short *)(puVar2 + 4) = (short)param_1;
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

