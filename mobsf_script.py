import subprocess
from utils import *
from tabulate import tabulate
import click

SERVER = "http://127.0.0.1:8000"


@click.group()
def main():
    pass


@main.group()
def cloud():
    pass


@main.group()
def mobile():
    pass


@main.group()
def gateway():
    pass


# ------------------------------- MOBSF Command -------------------------------
@mobile.command()
@click.argument('files', nargs=-1)
@click.option('--apikey', envvar='MOBSF_APIKEY', prompt=True, help='API key for authentication')
@click.option('--pdf', help='Generate PDF report')
def mobsf(files, apikey, pdf):
    """Scan and analyze APK files for security vulnerabilities using MobSF."""
    if not files:
        file1 = click.prompt("Enter the file path")
        file2 = click.prompt("Enter the file path of another apk package, enter \"n\" to skip")
        if file2 != "n":
            files = [file1, file2]
        else:
            files = [file1]
    """Process files and generate reports."""
    responses = [upload(file, apikey) for file in files]

    scan(responses[0], apikey)

    if not pdf:
        rep_json = json_resp(responses[0], apikey)
        new_rep_json = remove_non_security_related_keys(rep_json)
        j_dict = json.loads(new_rep_json)

        check_list, table_data = gen_table(j_dict)
        wrapped_data = [[item[0], wrap_text(item[1], width=150)] for item in table_data]
        check_lst = process_json(check_list)
        print(check_lst[0])
        print(check_lst[1])
        print(tabulate(wrapped_data, headers=["Key", "Value"], tablefmt="grid"))
    else:
        gen_pdf(responses[0], apikey, pdf)

    if len(files) == 2:
        scan(responses[1], apikey)
        if not pdf:
            rep_json_2 = json_resp(responses[1], apikey)
            new_rep_json_2 = remove_non_security_related_keys(rep_json_2)
            j_dict_2 = json.loads(new_rep_json_2)
            check_list_2, table_data_2 = gen_table(j_dict_2)
            check_lst_2 = process_json(check_list_2)
            print(check_lst_2[0])
            print(check_lst_2[1])
            wrapped_data_2 = [[item[0], wrap_text(item[1], width=150)] for item in table_data_2]
            print(tabulate(wrapped_data_2, headers=["Key", "Value"], tablefmt="grid"))

            hash1 = json.loads(responses[0])["hash"]
            hash2 = json.loads(responses[1])["hash"]
            comparison = compare(hash1, hash2, apikey)
            prettify_json(comparison)

        if pdf:
            gen_pdf(responses[1], apikey, pdf)


# ------------------------------- Cloud Command -------------------------------
@cloud.command()
@click.option('--name', prompt=True, help='Name of the Docker image to scan')
@click.option("--html", help="Specify the location to the HTML template file")
def trivy(name, html):
    """Run Trivy scan for a Docker image."""
    if html:
        trimmed_name = name.split("/")[-1]
        # Define the Trivy command
        output_file = f"{trimmed_name}.html"
        template_path = html
        cmd = [
            "trivy", "image",
            "--format", "template",
            "--template", f"@{template_path}",
            "-o", output_file,
            name
        ]
    else:
        cmd = ["trivy", "image", name]

    # Execute the Trivy command
    try:
        subprocess.run(cmd, check=True)
        click.echo("Scan completed successfully")
        if html:
            click.echo(f"The report is saved to {output_file}")
    except subprocess.CalledProcessError as e:
        click.echo("Trivy scan failed")
        click.echo(f"Details: {str(e)}")


if __name__ == '__main__':
    main()
