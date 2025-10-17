<div align="center">
  <img src="images/mutafuzz-logo.png" alt="MutaFuzz" width="500px">
  <br>
  <h3>Mutation-driven HTTP fuzzing for Burp Suite</h3>
  <br>

![Java](https://img.shields.io/badge/Java-21%2B-blue)
![Burp API](https://img.shields.io/badge/Montoya%20API-2025.8-orange)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-1.0.0-brightgreen)

</div>

---

MutaFuzz is a powerful Burp Suite extension that brings **Python scripting** to HTTP fuzzing. Built on the Montoya API, it provides a flexible, programmable fuzzing framework perfect for bug bounty hunting, penetration testing, and security research.

- **Python-Powered Fuzzing** - Full Python scripting with complete Montoya API access
- **Intelligent Learn Mode** - Automatically filter duplicate responses to surface only interesting results
- **Multiple Fuzzing Modes** - Three distinct modes for different fuzzing workflows
- **Multi-Instance Dashboard** - Run multiple fuzzing sessions simultaneously
- **Advanced Filtering** - Custom columns, complex queries, and smart result management

> **[📚 Read the full documentation at docs.mutafuzz.com →](https://docs.mutafuzz.com)**

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Use Cases](#use-cases)
- [Documentation](#documentation)
- [Requirements](#requirements)
- [Contributing](#contributing)
- [Acknowledgments](#acknowledgments)
- [License](#license)

## Features

### Python-Powered Fuzzing

Full Python scripting with decorator-based filters, response callbacks, and complete Montoya API access for building complex fuzzing logic.

### Intelligent Learn Mode

Automatically analyzes baseline responses to filter out noise:

- Calibration phase with random payloads
- Pattern detection by status, length, body hash
- Smart filtering to surface only interesting responses
- Multiple learn groups for different payload types

### Multiple Fuzzing Modes

**Single Request Mode** - Select text and fuzz with `%s` placeholders for quick parameter testing

**Multiple Requests Mode** - Send requests from Proxy History/Logger/Target for batch testing and application flow analysis

**Empty Panel Mode** - Build requests programmatically with Python for custom algorithms and API fuzzing

### Request Table Management

Advanced filtering syntax with operators, custom columns, smart ignore functionality with response fingerprinting, and results export.

### Multi-Instance Dashboard

Centralized management of multiple fuzzer instances with batch operations, combined results view, and progress tracking.

## Installation

### Option 1: GitHub Releases (Recommended)

1. Download the latest `mutafuzz-vX.Y.Z.jar` from [Releases](https://github.com/theblackturtle/mutafuzz/releases)
2. Open Burp Suite Professional
3. Navigate to **Extensions** → **Installed** → **Add**
4. Select **Java** as extension type
5. Choose the downloaded JAR file
6. Verify "MutaFuzz" tab appears in Burp

### Option 2: BApp Store

1. Open Burp Suite Professional
2. Navigate to **Extensions** → **BApp Store**
3. Search for "MutaFuzz"
4. Click **Install**

### Option 3: Build from Source

```bash
git clone https://github.com/theblackturtle/mutafuzz.git
cd mutafuzz
./gradlew build
# JAR will be in build/libs/
```

Then load the JAR file via **Extensions** → **Add** → **Java**.

## Use Cases

| Use Case                      | Description                                           | Example Script                                                                                        |
| ----------------------------- | ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| **Hidden Endpoint Discovery** | Fuzz for undocumented paths with Learn Mode filtering | [001_urls.py](src/main/resources/scripts/001_urls.py)                                                 |
| **Parameter Injection**       | Test URL/body parameter injections                    | [002_url_parameter_injection.py](src/main/resources/scripts/002_url_parameter_injection.py)           |
| **Multi-Step Exploitation**   | Chain requests with session state                     | [006_synchronous_request_chaining.py](src/main/resources/scripts/006_synchronous_request_chaining.py) |
| **Custom HTTP Requests**      | Build requests programmatically                       | [005_custom_http_requests.py](src/main/resources/scripts/005_custom_http_requests.py)                 |
| **API Fuzzing**               | Iterate through request lists                         | [005_request_list.py](src/main/resources/scripts/005_request_list.py)                                 |

### Feature Comparison

| Feature            | MutaFuzz              | Burp Intruder              |
| ------------------ | --------------------- | -------------------------- |
| Python Scripting   | Full language support | Limited payload processing |
| Learn Mode         | Automatic filtering   | Manual only                |
| Request Chaining   | Multi-step `.send()`  | Limited                    |
| Session State      | Thread-safe storage   | Not available              |
| Decorator Filters  | Composable filters    | Config-only                |
| Custom Columns     | Programmatic          | Limited                    |
| Montoya API Access | Full access           | N/A                        |

## Documentation

**Get started in 5 minutes** with our comprehensive documentation:

- **[Full Documentation](https://docs.mutafuzz.com)** - Complete guide to MutaFuzz
- **[Quick Start Tutorial](https://docs.mutafuzz.com/quickstart)** - Your first fuzzing session
- **[Installation Guide](https://docs.mutafuzz.com/installation)** - Detailed installation instructions
- **[Usage Modes](https://docs.mutafuzz.com/modes)** - Single Request, Multiple Requests, Empty Panel
- **[Python API Reference](https://docs.mutafuzz.com/scripting)** - Complete API documentation (58 methods)
- **[Learn Mode Guide](https://docs.mutafuzz.com/scripting/learn-mode)** - Master intelligent response filtering
- **[Request Table Filtering](https://docs.mutafuzz.com/request-table/filtering)** - Advanced filtering syntax
- **[Dashboard Management](https://docs.mutafuzz.com/dashboard)** - Multi-instance fuzzing
- **[Example Scripts](src/main/resources/scripts/)** - Ready-to-use fuzzing scripts
- **[FAQ](https://docs.mutafuzz.com/faq)** - Common questions and troubleshooting

## Requirements

**Important:** MutaFuzz requires Burp Suite Professional. It will NOT work with Burp Suite Community Edition.

- **Burp Suite Professional** 2025.3 or later
- **Java** 21 or later
- **Montoya API** support (included in Burp Suite Pro 2025.3+)

### Language Constraints

- Scripts use **Jython 2.7** (Python 2.7 syntax on JVM)
- No Python 3 features (f-strings, type hints, etc.)
- Full Java interop available for advanced use cases

## Contributing

Contributions are welcome! To build and test MutaFuzz:

```bash
# Clone repository
git clone https://github.com/theblackturtle/mutafuzz.git
cd mutafuzz

# Build with Gradle
./gradlew build

# Run tests
./gradlew test

# JAR output
ls build/libs/mutafuzz-*.jar
```

### Development Guidelines

- Follow existing code style
- Add tests for new features
- Update documentation for API changes
- Test with Burp Suite Pro before submitting PR

Submit pull requests to the `main` branch.

## Support & Community

- **Author**: [@thebl4ckturtle](https://x.com/thebl4ckturtle)
- **GitHub**: [github.com/theblackturtle/mutafuzz](https://github.com/theblackturtle/mutafuzz)
- **Issues**: [Report bugs or request features](https://github.com/theblackturtle/mutafuzz/issues)
- **Documentation**: [https://docs.mutafuzz.com](https://docs.mutafuzz.com)

## Acknowledgments

MutaFuzz was inspired by [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder) by [James Kettle](https://github.com/albinowax).

## License

MutaFuzz is distributed under the MIT License.

---

<div align="center">
  Made with ❤️ by <a href="https://x.com/thebl4ckturtle">@thebl4ckturtle</a>
</div>
