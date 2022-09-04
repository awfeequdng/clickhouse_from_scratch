#include "Settings.h"

#include <Poco/Util/AbstractConfiguration.h>
#include <Common/typeid_cast.h>
#include <string.h>

namespace DB
{

namespace ErrorCodes
{
    extern const int THERE_IS_NO_PROFILE;
    extern const int NO_ELEMENTS_IN_CONFIG;
    extern const int UNKNOWN_ELEMENT_IN_CONFIG;
}

IMPLEMENT_SETTINGS_TRAITS(SettingsTraits, LIST_OF_SETTINGS)

/** Set the settings from the profile (in the server configuration, many settings can be listed in one profile).
    * The profile can also be set using the `set` functions, like the `profile` setting.
    */
void Settings::setProfile(const String & profile_name, const Poco::Util::AbstractConfiguration & config)
{
    String elem = "profiles." + profile_name;

    if (!config.has(elem))
        throw Exception("There is no profile '" + profile_name + "' in configuration file.", ErrorCodes::THERE_IS_NO_PROFILE);

    Poco::Util::AbstractConfiguration::Keys config_keys;
    config.keys(elem, config_keys);

    for (const std::string & key : config_keys)
    {
        if (key == "constraints")
            continue;
        if (key == "profile" || key.starts_with("profile["))   /// Inheritance of profiles from the current one.
            setProfile(config.getString(elem + "." + key), config);
        else
            set(key, config.getString(elem + "." + key));
    }
}

void Settings::loadSettingsFromConfig(const String & path, const Poco::Util::AbstractConfiguration & config)
{
    if (!config.has(path))
        throw Exception("There is no path '" + path + "' in configuration file.", ErrorCodes::NO_ELEMENTS_IN_CONFIG);

    Poco::Util::AbstractConfiguration::Keys config_keys;
    config.keys(path, config_keys);

    for (const std::string & key : config_keys)
    {
        set(key, config.getString(path + "." + key));
    }
}

void Settings::checkNoSettingNamesAtTopLevel(const Poco::Util::AbstractConfiguration & config, const String & config_path)
{
    if (config.getBool("skip_check_for_incorrect_settings", false))
        return;

    Settings settings;
    for (auto setting : settings.all())
    {
        const auto & name = setting.getName();
        if (config.has(name))
        {
            throw Exception(fmt::format("A setting '{}' appeared at top level in config {}."
                " But it is user-level setting that should be located in users.xml inside <profiles> section for specific profile."
                " You can add it to <profiles><default> if you want to change default value of this setting."
                " You can also disable the check - specify <skip_check_for_incorrect_settings>1</skip_check_for_incorrect_settings>"
                " in the main configuration file.",
                name, config_path),
                ErrorCodes::UNKNOWN_ELEMENT_IN_CONFIG);
        }
    }
}

IMPLEMENT_SETTINGS_TRAITS(FormatFactorySettingsTraits, FORMAT_FACTORY_SETTINGS)

}
