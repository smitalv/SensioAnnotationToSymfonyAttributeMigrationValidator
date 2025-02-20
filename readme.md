# Symfony Command: Sensio Annotation To Symfony Attribute Migration Validator

## Overview
This Symfony command scans your project for Sensio annotations and Symfony attributes, extracting them into a structured YAML file. This ensures a safe migration process by preserving all security annotations and attributes during the transition.

## Features
- Parses Sensio FrameworkExtraBundle annotations (`@Security`)
- Extracts Symfony 6+ attributes (`#[IsGranted]`)
- Outputs the extracted data into a YAML file for verification
- Helps prevent data loss during migration from annotations to attributes

## Usage
- Ensure you have Symfony installed in your project
- Copy command file to your project
- Register the command in your `config/services.yaml` file
- Run the command with `bin/console app:validate-security-annotations`
- Verify the output in the `annotations.yaml` file
- Add the file to your version control system
- Migrate your annotations to attributes
- Verify the output in the `annotations.yaml` file (diff is empty)
- Remove the command and the output file from your project

## Notice
This command is intended to be used as a helper tool during the migration process. It is not a replacement for manual verification and should not be used in production environments.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```