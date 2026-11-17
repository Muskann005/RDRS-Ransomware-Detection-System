
from src.entropy_detector import detect_suspicious_entropy


def analyze_data(data):
    result = detect_suspicious_entropy(data)

    return {
        "module": "Entropy Analysis",
        "input": data,
        "entropy_score": result["entropy"],
        "status": result["status"],
        "alert": result["alert"]
    }


if __name__ == "__main__":
    sample = "aB9$xK2@mP7#qL5!vN8&zR4"

    print(analyze_data(sample))
