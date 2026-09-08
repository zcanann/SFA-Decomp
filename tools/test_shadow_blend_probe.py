import unittest

from shadow_blend_probe import encode, reference


class BlendOracleTests(unittest.TestCase):
    def test_contributions_round_separately_and_alpha_is_cleared(self):
        self.assertEqual(reference([(2, 4, 6, 255)], [(1, 3, 5, 128)], 0.5, 6), [(0, 2, 4, 0)])

    def test_endpoints_still_use_255_over_256(self):
        a, b = [(255, 128, 1, 99)], [(64, 32, 16, 77)]
        self.assertEqual(reference(a, b, 1.0, 6), [(254, 127, 0, 0)])
        self.assertEqual(reference(a, b, 0.0, 6), [(63, 31, 15, 0)])

    def test_weight_wraps_instead_of_clamping(self):
        a, b = [(255, 255, 255, 255)], [(0, 0, 0, 255)]
        self.assertEqual(reference(a, b, -1.0, 6), [(0, 0, 0, 0)])
        self.assertEqual(reference(a, b, 1.5, 6), [(125, 125, 125, 0)])

    def test_rgb565_expansion_and_repacking(self):
        self.assertEqual(reference([0xF800], [0x001F], 0.5, 4), [0x780F])
        self.assertEqual(reference([0xFFFF], [0xFFFF], 0.5, 4), [0xFFFF])

    def test_rgba8_plane_order(self):
        self.assertEqual(encode([(1, 2, 3, 4)] * 16, 4, 4, 6), bytes([4, 1]) * 16 + bytes([2, 3]) * 16)

    def test_rgb565_tile_order(self):
        image = list(range(32))
        result = encode(image, 8, 4, 4)
        words = [int.from_bytes(result[i:i + 2], 'big') for i in range(0, len(result), 2)]
        self.assertEqual(words, [0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27,
                                 4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31])


if __name__ == '__main__':
    unittest.main()
