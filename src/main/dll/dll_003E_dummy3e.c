
/* ===== EN v1.0 retargeted leaves ========================================= */

/* EN v1.0 0x80131570  size: 12b  Read changed bit from item->flags. */

/* EN v1.0 0x8013157C  size: 20b  Set item->value and item->frameDelay = 2.
 * Logic-only ? target has `extsh r0,r4; sth r0,0xc(r3)` but MWCC -O4
 * strips the redundant extsh before sth (same family as GameUI_func0F /
 * CMenu_SetShouldClose). */

/* EN v1.0 0x80131590  size: 8b   Getter for item->value. */

/* EN v1.0 0x80131598  size: 116b  Toggle enabled bit on item->flags. */

/* EN v1.0 0x8013160C  size: 12b  Read enabled bit from item->flags. */

/* EN v1.0 0x80131618  size: 808b  Render title menu item. */

/* EN v1.0 0x80131940  size: 948b  Update title menu item input state. */

/* EN v1.0 0x80132008  size: 8b   Trivial 1-returner. */

int Dummy3E_func05_ret_1(void) { return 1; }

/* EN v1.0 0x80132010  size: 4b   Empty no-op. */
void Dummy3E_func04_nop(void)
{
}

/* EN v1.0 0x80132014  size: 8b   Trivial 0-returner. */
int Dummy3E_func03_ret_0(void) { return 0; }

/* EN v1.0 0x8013201C  size: 4b   Empty no-op. */
void Dummy3E_release(void)
{
}

/* EN v1.0 0x80132020  size: 4b   Empty no-op. */
void Dummy3E_initialise(void)
{
}

/* EN v1.0 0x80131540  size: 48b  Toggle A-button bit of item->flags. */

/* EN v1.0 0x80131CF4  size: 32b  Wrapper for mm_free. */

/* EN v1.0 0x80131FE0  size: 40b  Zero 6 u32s at lbl_803A9DB8. */

/* EN v1.0 0x80131D14  size: 168b  Create text-window title menu item. */

/* EN v1.0 0x80131DBC  size: 164b  Create simple title menu item. */

/* EN v1.0 0x80131E60  size: 172b  Create text-backed title menu item. */
