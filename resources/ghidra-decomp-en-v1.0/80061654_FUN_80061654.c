// Function: FUN_80061654
// Entry: 80061654
// Size: 768 bytes

void FUN_80061654(int param_1,int param_2)

{
  uint uVar1;
  undefined4 uVar2;
  undefined2 *puVar3;
  uint local_98;
  uint local_94;
  undefined auStack144 [64];
  float local_50;
  float local_4c;
  float local_48;
  float local_40;
  float local_3c;
  float local_38;
  float local_30;
  float local_2c;
  float local_28;
  
  puVar3 = *(undefined2 **)(param_2 + 0x54);
  if (*(char *)(puVar3 + 0xc) == '\0') {
    FUN_8006135c(puVar3,param_1);
  }
  if (*(char *)(puVar3 + 0xc) != -1) {
    uVar1 = FUN_80062378(param_1,0x96);
    local_94 = local_94 & 0xffffff00 | uVar1 & 0xff;
    if ((uVar1 & 0xff) != 0) {
      uVar2 = FUN_8000f54c();
      FUN_8002b47c(param_1,&local_50,0);
      local_50 = FLOAT_803dec68;
      local_4c = FLOAT_803dec58;
      local_48 = FLOAT_803dec58;
      local_40 = FLOAT_803dec58;
      local_3c = FLOAT_803dec68;
      local_38 = FLOAT_803dec58;
      local_30 = FLOAT_803dec58;
      local_2c = FLOAT_803dec58;
      local_28 = FLOAT_803dec68;
      FUN_80246eb4(uVar2,&local_50,auStack144);
      FUN_8025d0a8(auStack144,0x1b);
      FUN_802573f8();
      FUN_80256978(9,1);
      FUN_80256978(0xd,1);
      FUN_802581e0(1);
      FUN_80257f10(0,1,4,0x3c,0,0x7d);
      local_98 = local_94;
      FUN_8025bdac(0,&local_98);
      FUN_8025be8c(0,0x1c);
      FUN_8025c2a0(1);
      FUN_8025b6f0(0);
      FUN_80259ea4(4,0,0,0,0,0,2);
      FUN_80259ea4(5,0,0,0,0,0,2);
      FUN_80259e58(0);
      FUN_8025c0c4(0,0,0,0xff);
      FUN_8025b71c(0);
      FUN_8025ba40(0,0xf,0xf,0xf,0xf);
      FUN_8025bac0(0,7,6,4,7);
      FUN_8025bb44(0,0,0,0,1,0);
      FUN_8025bc04(0,0,0,0,1,0);
      FUN_80070310(1,3,0);
      FUN_80258b24(0);
      FUN_8025d124(0x1b);
      FUN_8025c584(1,4,5,5);
      FUN_8004c2e4(*(undefined4 *)(*(int *)(param_1 + 100) + 4),0);
      FUN_8025889c(0x80,6,4);
      write_volatile_2(0xcc008000,*puVar3);
      write_volatile_2(0xcc008000,puVar3[1]);
      write_volatile_2(0xcc008000,puVar3[2]);
      write_volatile_2(0xcc008000,0);
      write_volatile_2(0xcc008000,0);
      write_volatile_2(0xcc008000,puVar3[3]);
      write_volatile_2(0xcc008000,puVar3[4]);
      write_volatile_2(0xcc008000,puVar3[5]);
      write_volatile_2(0xcc008000,0x400);
      write_volatile_2(0xcc008000,0);
      write_volatile_2(0xcc008000,puVar3[6]);
      write_volatile_2(0xcc008000,puVar3[7]);
      write_volatile_2(0xcc008000,puVar3[8]);
      write_volatile_2(0xcc008000,0x400);
      write_volatile_2(0xcc008000,0x400);
      write_volatile_2(0xcc008000,puVar3[9]);
      write_volatile_2(0xcc008000,puVar3[10]);
      write_volatile_2(0xcc008000,puVar3[0xb]);
      write_volatile_2(0xcc008000,0);
      write_volatile_2(0xcc008000,0x400);
      FUN_8025d124(0);
    }
  }
  return;
}

