// Function: FUN_8021eb18
// Entry: 8021eb18
// Size: 528 bytes

void FUN_8021eb18(int param_1)

{
  int iVar1;
  char cVar2;
  uint *puVar3;
  undefined auStack24 [4];
  undefined auStack20 [4];
  undefined auStack16 [8];
  
  puVar3 = *(uint **)(param_1 + 0xb8);
  iVar1 = FUN_80036770(param_1,0,0,0,auStack24,auStack20,auStack16);
  if ((iVar1 != 0) &&
     ((((*(short *)(puVar3 + 0x9d) == 4 || (((int)*(short *)(puVar3 + 0x9d) - 9U & 0xffff) < 2)) ||
       ((iVar1 != 0xf && (iVar1 != 0xe)))) && (*(short *)(puVar3 + 0x306) != 0)))) {
    FUN_80221e94((double)FLOAT_803e6b40,param_1,auStack24);
    iVar1 = FUN_800221a0(0,0);
    FUN_800392f0(param_1,puVar3 + 0xef,&DAT_803dc308 + iVar1 * 6,1);
    if ((int)*(short *)(puVar3 + 0x9d) != 3) {
      puVar3[0x30f] = (int)*(short *)(puVar3 + 0x9d);
    }
    if ((*(short *)(puVar3 + 0x9d) == 2) || (*(short *)(puVar3 + 0x9d) == 8)) {
      *(short *)(puVar3 + 0x306) = *(short *)(puVar3 + 0x306) + -1;
      FUN_8009a8c8((double)FLOAT_803e6b30,param_1);
      if (*(short *)(puVar3 + 0x306) < 1) {
        (**(code **)(*DAT_803dca68 + 0x60))();
        *(byte *)((int)puVar3 + 0xc49) = *(byte *)((int)puVar3 + 0xc49) & 0xfe;
        FUN_800200e8(0x634,0);
        cVar2 = FUN_8002e04c();
        if (cVar2 != '\0') {
          iVar1 = FUN_8002bdf4(0x2c,0xd4);
          *(undefined *)(iVar1 + 4) = 2;
          *(undefined4 *)(iVar1 + 8) = *(undefined4 *)(param_1 + 0xc);
          *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(param_1 + 0x10);
          *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(param_1 + 0x14);
          *(undefined2 *)(iVar1 + 0x1a) = 0x675;
          *(undefined2 *)(iVar1 + 0x1c) = 0;
          *(undefined2 *)(iVar1 + 0x1e) = 0xffff;
          FUN_8002df90(iVar1,5,(int)*(char *)(param_1 + 0xac),0xffffffff,
                       *(undefined4 *)(param_1 + 0x30));
        }
        *(undefined2 *)(param_1 + 2) = 0;
        *(undefined2 *)(param_1 + 4) = 0;
        *(undefined *)((int)puVar3 + 0x25f) = 0;
        *puVar3 = *puVar3 | 0x1000000;
        FUN_800200e8(0xb48,1);
        (**(code **)(*DAT_803dca68 + 0x60))();
      }
    }
    else {
      (**(code **)(*DAT_803dca8c + 0x14))(param_1,puVar3,3);
    }
  }
  return;
}

