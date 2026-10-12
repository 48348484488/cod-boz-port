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
                "pixel_trail": [
                    "[BOZ_GL_PIXEL_TRAIL] frame=300 order=900 kind=arrays seq=490 "
                    "program=12 tex=0 bottom=1c1a19 middle=837978 "
                    "top=1c1a19 count=4",
                    "[BOZ_GL_PIXEL_TRAIL] frame=300 order=901 kind=elements seq=413 "
                    "program=18 tex=62 bottom=1c1a19 middle=837978 "
                    "top=1c1a19 count=108"
                ],
                "array_geometry": [
                    "[BOZ_GL_ARRAY_PROGRAM] frame=300 program=15 mode=0004 "
                    "first=0 count=4 fbo=0 tex=0 order=900",
                    "[BOZ_GL_ARRAY_ATTR] frame=300 program=15 "
                    "name=inPosition loc=0 enabled=1 size=2 "
                    "type=1406 stride=16 vbo=0 ptr=4a123400"
                ],
                "array_ab_events": [
                    "[BOZ_GL_ARRAY_AB] frame=305 draw=490 "
                    "no_cull=1 force_blend=0 changed_cull=1 changed_blend=0"
                ],
                "layer_ab_events": [
                    "[BOZ_GL_LAYER_AB] frame=305 draw=492 program=15 "
                    "tex=379 skipped=1 mode=0005 count=4",
                    "[BOZ_GL_LAYER_AB] frame=315 draw=672 program=15 "
                    "tex=380 skipped=1 mode=0005 count=4"
                ],
                "image_grid": [
                    "[BOZ_GL_IMAGE_GRID] tex=379 size=1024x1024 samples=25 "
                    "unique_rgb=1 alpha_nonzero=25 min=837978 max=837978"
                ],
                "stage_capture": [
                    "[BOZ_GL_STAGE_CAPTURE] frame=300 stage=before-379 "
                    "draw=849 tex=379 bytes=921600 ok=1"
                ],
                "sprite_quads": [
                    "[BOZ_GL_SPRITE_QUAD] frame=300 order=850 tex=379 "
                    "image=1024x1024 uploads=1 valid=1 "
                    "rect=0,0,640,480 uv=0,0,4096,8192 "
                    "scale=0.000244141,0.00012207 offset=0,0 "
                    "norm=0,0 sampler_unit=0 sampler_tex=379"
                ],
                "sprite_pipeline": [
                    "[BOZ_GL_SPRITE_PIPELINE] frame=300 order=850 program=15 "
                    "tracked_tex=379 active=84c0 actual_active_tex=379 "
                    "blend=1 src=0302 dst=0303"
                ],
                "uv_ab_events": [
                    "[BOZ_GL_UV_AB] frame=305 tex=379 program=15 "
                    "sample=0.05,0.05 saved_scale=0.000244141,0.000244141 "
                    "saved_offset=0,0"
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
        self.assertEqual(len(result["pixel_trail"]), 2)
        self.assertEqual(len(result["array_geometry"]), 2)
        self.assertEqual(len(result["array_ab_events"]), 1)
        self.assertEqual(len(result["layer_ab_events"]), 2)
        self.assertEqual(len(result["image_grid"]), 1)
        self.assertEqual(len(result["stage_capture"]), 1)
        self.assertEqual(len(result["sprite_quads"]), 1)
        self.assertEqual(len(result["sprite_pipeline"]), 1)
        self.assertEqual(len(result["uv_ab_events"]), 1)
        self.assertFalse(result["visual_frontend_verified"])


if __name__ == "__main__":
    unittest.main()
