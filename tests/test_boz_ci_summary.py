"""Host-only regression tests for asset-free BOZ runtime summaries."""
import unittest

from tools.boz_ci_summary import draw_dimensions, parse_draw_census, summarize


class BozSummaryTests(unittest.TestCase):
    def test_draw_dimensions(self):
        self.assertEqual(draw_dimensions(
            "[BOZ_GL_TEXTURE_DRAW] seq=1 image=2x2 sampler0_tex=58"), (2, 2))
        self.assertEqual(draw_dimensions(
            "[BOZ_GL_TEXTURE_DRAW] image=1024x512"), (1024, 512))
        self.assertIsNone(draw_dimensions("[BOZ_GL_DRAW] seq=1"))

    def test_census_parser(self):
        line = (
            "[BOZ_GL_DRAW_CENSUS] swap=150 frame_draws=1 frame_2x2=1 "
            "frame_large=0 frame_unknown=0 total_draws=149 total_2x2=149 "
            "total_large=0 total_unknown=0 large_known=23 large_drawn=0 "
            "last_tex=59 last_size=2x2"
        )
        data = parse_draw_census(line)
        self.assertEqual(data["swap"], 150)
        self.assertEqual(data["large_known"], 23)
        self.assertEqual(data["large_drawn"], 0)
        self.assertEqual(data["total_2x2"], 149)
        self.assertEqual(parse_draw_census("[BOZ_GL_TEXTURE_DRAW] seq=1"), {})

    def test_hash_difference_is_not_proof_of_menu(self):
        frame = lambda n, sha: {
            "file": f"/tmp/boz-swap-{n:05d}.png",
            "sha256": sha,
            "top_rgb": [{"rgb": "000000", "pixels": 307015},
                        {"rgb": "c0c0ff", "pixels": 185}],
            "distinct_rgb_colors": 2,
        }
        report = {
            "fast_property": {
                "captured_pngs": [frame(100, "before"), frame(140, "after")],
                "diagnostic_tap_events": ["press", "release"],
            },
            "fast_texture_evidence": {
                "draws": [
                    "[BOZ_GL_TEXTURE_DRAW] image=2x2 seq=1",
                    "[BOZ_GL_TEXTURE_DRAW] image=512x512 seq=2",
                ],
                "draw_census": [
                    "[BOZ_GL_DRAW_CENSUS] swap=150 total_draws=149 "
                    "total_2x2=149 total_large=0 large_known=23 large_drawn=0"
                ],
                "unit0_binds": [
                    "[BOZ_GL_UNIT0_BIND] seq=2 draw=1 old=58 tex=59"
                ],
                "sampler_bindings": [
                    "[BOZ_GL_SAMPLER_BIND] seq=2 program=9 name=uTexture "
                    "type=8b5e unit=15 tex=56 image=512x512 uploads=1"
                ],
                "draw_states": [
                    "[BOZ_GL_DRAW_STATE] seq=2 program=9 blend=1 "
                    "src=0302 dst=0303 depth=0 cull=0"
                ],
                "uv_states": [
                    "[BOZ_GL_UV_STATE] seq=2 program=9 scale_loc=1 "
                    "scale=0.000976562,0.001953125 offset_loc=2 offset=0,0"
                ],
                "texture_params": [
                    "[BOZ_GL_TEXTURE_PARAMS] seq=2 program=9 tex=56 "
                    "min=2601 mag=2601 wrap_s=812f wrap_t=812f"
                ],
                "clear_causes": [
                    "[BOZ_GL_CLEAR_CAUSE] frame=300 mask=4000 fbo=0 "
                    "rgba=0.5,0.5,0.5,1 scissor_on=0 rect=0,0,640,480"
                ],
            },
        }
        result = summarize(report)
        self.assertTrue(result["after_tap_frame_changed"])
        self.assertTrue(result["after_tap_color_counts_identical"])
        self.assertEqual(result["sampled_draws_with_2x2_texture"], 1)
        self.assertEqual(result["sampled_draws_with_larger_texture"], 1)
        self.assertEqual(result["last_draw_census"]["large_drawn"], 0)
        self.assertEqual(len(result["unit0_binding_transitions"]), 1)
        self.assertEqual(len(result["sampler_bindings"]), 1)
        self.assertEqual(len(result["draw_states"]), 1)
        self.assertEqual(len(result["uv_states"]), 1)
        self.assertEqual(len(result["texture_params"]), 1)
        self.assertEqual(len(result["clear_causes"]), 1)
        self.assertFalse(result["visual_frontend_verified"])


if __name__ == "__main__":
    unittest.main()
