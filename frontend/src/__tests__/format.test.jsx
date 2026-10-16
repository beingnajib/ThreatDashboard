import * as format from "../lib/format";

const { defang, riskBand, timeAgo } = format;
import { formatError as apiFormatError } from "../lib/api";

describe("format helpers", () => {
  it("bands risk scores", () => {
    expect(riskBand(95)).toBe("critical");
    expect(riskBand(60)).toBe("high");
    expect(riskBand(40)).toBe("medium");
    expect(riskBand(5)).toBe("low");
  });

  it("defangs indicators", () => {
    expect(defang("http://evil.example/x")).toBe("hxxp://evil[.]example/x");
  });

  it("describes elapsed time", () => {
    expect(timeAgo(new Date(Date.now() - 2 * 3600 * 1000).toISOString())).toBe("2h ago");
    expect(timeAgo(null)).toBe("—");
  });

  it("flattens DRF error payloads", () => {
    expect(apiFormatError({ value: ["Invalid."], non_field_errors: ["Nope."] })).toBe("value: Invalid. Nope.");
    expect(apiFormatError({ detail: "Not found." })).toBe("Not found.");
    expect(format.formatError).toBeUndefined();
  });
});
