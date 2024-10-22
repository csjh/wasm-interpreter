import os

test_dir = os.path.dirname(os.path.realpath(__file__))

for file in os.listdir("core"):
    if file.endswith(".wast"):
        without_wast = file[: -len(".wast")]
        input_path = os.path.join(test_dir, "core", file)
        output_path = os.path.join(
            test_dir, "core/wast-json", f"{without_wast}-wast.json"
        )
        if os.system(f"wast2json {input_path} -o {output_path}") != 0:
            print(f"Failed to convert {input_path} to wast-json")
            break

        if os.system(f"./executor {output_path}") != 0:
            print(f"Failed: {output_path}")
            break
        print(f"Passed: {output_path}")
