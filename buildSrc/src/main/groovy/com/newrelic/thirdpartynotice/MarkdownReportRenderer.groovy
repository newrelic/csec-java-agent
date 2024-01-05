package com.newrelic.thirdpartynotice
import com.github.jk1.license.ImportedModuleData
import com.github.jk1.license.License
import com.github.jk1.license.ManifestData
import com.github.jk1.license.ModuleData
import com.github.jk1.license.PomData
import com.github.jk1.license.ProjectData
import com.github.jk1.license.render.*

class MarkdownReportRenderer extends InventoryReportRenderer {

    MarkdownReportRenderer(String fileName = 'licenses.md', String name = null, File overridesFilename = null) {
        this.name = name
        this.fileName = fileName
        if (overridesFilename) overrides = parseOverrides(overridesFilename)
    }

    @Override
    void render(ProjectData data) {
        project = data.project
        if( name == null ) name = project.name
        config = project.licenseReport
        output = new File(config.outputDir, fileName)
        output.delete()
        def inventory = buildLicenseInventory(data)
        def externalInventories = buildExternalInventories(data)
        printDependencies(inventory, externalInventories)

    }

    private void printDependencies(Map<String, List<ModuleData>> inventory, Map<String, Map<String, List<ImportedModuleData>>> externalInventories) {
        output << "# Third Party Notices\n" +
                "\n" +
                "The New Relic Security Java agent uses source code from third party libraries which carry\n" +
                "their own copyright notices and license terms. These notices are provided\n" +
                "below.\n" +
                "\n" +
                "In the event that a required notice is missing or incorrect, please notify us\n" +
                "by e-mailing [opensource@newrelic.com](dependency-license/mailto:opensource@newrelic.com).\n" +
                "\n" +
                "For any licenses that require the disclosure of source code, the source code\n" +
                "can be found at https://github.com/newrelic/.\n" +
                "\n"

        output << "### Dependencies \n\n"
        inventory.keySet().sort().each { String license ->
//            output << "## ${license}\n\n"
            inventory[license].sort({ ModuleData a, ModuleData b -> a.group <=> b.group }).each { ModuleData data ->
                printDependency(data)
            }
        }

        externalInventories.keySet().sort().each { String name ->
//            output << "## ${name}\n\n"
            externalInventories[name].each { String license, List<ImportedModuleData> dependencies ->
                output << "\n"
                dependencies.each { ImportedModuleData importedData ->
                    printImportedDependency(importedData)
                }
            }
        }
        output << "\n"
        output << "##### Note regarding transitive dependencies \n\n"
        output << "Depending on your existing libraries and package management settings, your systems may call externally maintained libraries in addition to those listed above. " +
                "Please refer to such transitive dependency projects regarding applicable licenses and notices."
    }

    private void printDependency(ModuleData data) {
        boolean projectUrlDone = false
        output << "**${++counter}**. "
        if (data.group) output << "**Group:** `$data.group` "
        if (data.name) output << "**Name:** `$data.name` "
        if (data.version) output << "**Version:** `$data.version` "
        output << "\n"

        String gnv = "${data.group}:${data.name}:${data.version}"
        if (overrides.containsKey(gnv)) {
            output << sectionLink("Project URL", overrides[gnv].projectUrl, overrides[gnv].projectUrl)
            output << sectionLink("License URL", overrides[gnv].license, overrides[gnv].licenseUrl)
        } else {
            if (!data.manifests.isEmpty() && !data.poms.isEmpty()) {
                ManifestData manifest = data.manifests.first()
                PomData pomData = data.poms.first()
                if (manifest.url && pomData.projectUrl && manifest.url == pomData.projectUrl) {
                    output << sectionLink("Project URL", manifest.url, manifest.url)
                    projectUrlDone = true
                }
            }

            if (!data.manifests.isEmpty()) {
                ManifestData manifest = data.manifests.first()
                if (manifest.url && !projectUrlDone) {
                    output << sectionLink("Manifest Project URL", manifest.url, manifest.url)
                }
                if (manifest.license) {
                    if (manifest.license.startsWith("http")) {
                        output << sectionLink("Manifest license URL", manifest.license, manifest.license)
                    } else if (manifest.hasPackagedLicense) {
                        output << sectionLink("Packaged License File", manifest.license, manifest.url)
                    } else {
                        output << section("Manifest License", "${manifest.license} (Not Packaged)")
                    }
                }
            }

            if (!data.poms.isEmpty()) {
                PomData pomData = data.poms.first()
                if (pomData.projectUrl && !projectUrlDone) {
                    output << sectionLink("POM Project URL", pomData.projectUrl, pomData.projectUrl)
                }
                if (pomData.licenses) {
                    pomData.licenses.each { License license ->
                        if (license.url) {
                            output << section("POM License", "${license.name} - ${license.url.startsWith("http") ? link(license.url, license.url) : section("License", license.url)}")
                        } else {
                            output << section("POM License", license.name)
                        }
                    }
                }
            }
        }

        if (!data.licenseFiles.isEmpty() && !data.licenseFiles.first().fileDetails.isEmpty()) {
            output << section("Embedded license files", data.licenseFiles.first().fileDetails.collect {
                link(config.outputDir + "/" + it.file, it.file)
            }.unique().join(' \n    - '))
        }
        output << "\n"
    }

    private printImportedDependency(ImportedModuleData data) {
        output << "\n\n"
        output << "${++counter}. **${data.name} v${data.version}**\n"
        output << sectionLink("Project URL", data.projectUrl, data.projectUrl)
        output << sectionLink("License URL", data.license, data.licenseUrl)
        output << "\n\n"
    }

    private GString section(String label, String value) {
        "> - **${label}**: ${value}\n"
    }

    private GString link(String name, String url) {
        "[${url}](${name})"
    }

    private GString sectionLink(String label, String name, String url) {
        section(label, link(name, url))
    }

    private String safeGet(String[] arr, int index) {
        arr.length > index ? arr[index] : null
    }

}