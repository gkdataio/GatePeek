# README artwork

Original GKData diagrams generated locally with Pillow. The animation is a conceptual illustration, not live telemetry or a claim about testing results. The GIFs have a 5.76-second loop. Static PNGs serve reduced-motion preferences; a portrait composition serves narrow screens. All assets are stored in the repository, with no runtime requests to badge or stats services.

Rebuild from the repository root:

```sh
python -m pip install Pillow
python docs/assets/readme/build_art.py
```

Edit `artwork.json` for titles, labels, colors, and the illustration selection. Use `--stills` for a fast layout pass. The generator uses local Arial Black, Segoe UI, and Consolas on Windows, or DejaVu fonts on Linux. Fonts are not bundled. `--font-dir PATH` chooses another directory containing those font filenames. Review text metrics if rebuilding with different fonts.

After editing, check both compositions, the image links in the README, and reduced-motion behavior. The readable README text contains the essential information independently of the artwork.
