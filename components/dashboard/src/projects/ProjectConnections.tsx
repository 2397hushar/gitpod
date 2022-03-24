/**
 * Copyright (c) 2021 Gitpod GmbH. All rights reserved.
 * Licensed under the GNU Affero General Public License (AGPL).
 * See License-AGPL.txt in the project root for license information.
 */

import { useContext, useEffect, useState } from "react";
import { useLocation } from "react-router";
import { Connection, Project, Team } from "@gitpod/gitpod-protocol";
// import CheckBox from "../components/CheckBox";
import { getCurrentTeam, TeamsContext } from "../teams/teams-context";
import { PageWithSubMenu } from "../components/PageWithSubMenu";
// import PillLabel from "../components/PillLabel";
import { ProjectContext } from "./project-context";
import { getGitpodService } from "../service/service";
import PillLabel from "../components/PillLabel";
import CheckBox from "../components/CheckBox";

// TODO(at) retrieve from server
export function getMockedConnectionTypes() {
    return [
        {
            id: "tailscale",
            attributes: ["authKey"],
        },
    ];
}

export function getProjectConnectionsMenu(project?: Project, team?: Team) {
    const teamOrUserSlug = !!team ? "t/" + team.slug : "projects";
    return [
        {
            title: "General",
            link: [`/${teamOrUserSlug}/${project?.slug || project?.name}/settings`],
        },
        {
            title: "Connections",
            link: [`/${teamOrUserSlug}/${project?.slug || project?.name}/connections`],
        },
        {
            title: "Configuration",
            link: [`/${teamOrUserSlug}/${project?.slug || project?.name}/configure`],
        },
        {
            title: "Variables",
            link: [`/${teamOrUserSlug}/${project?.slug || project?.name}/variables`],
        },
    ];
}

export function ProjectConnectionsPage(props: { project?: Project; children?: React.ReactNode }) {
    const location = useLocation();
    const { teams } = useContext(TeamsContext);
    const team = getCurrentTeam(location, teams);

    return (
        <PageWithSubMenu
            subMenu={getProjectConnectionsMenu(props.project, team)}
            title="Connections"
            subtitle="Manage project connections"
        >
            {props.children}
        </PageWithSubMenu>
    );
}

export default function () {
    const { project } = useContext(ProjectContext);

    const [connections, setConnections] = useState<Connection[]>([]);

    useEffect(() => {
        if (!project) {
            return;
        }
        updateConnections();
    }, [project]);

    const updateConnections = async () => {
        if (!project) {
            return;
        }
        const connections = await getGitpodService().server.getProjectConnections(project.id);
        setConnections(connections);
    };

    const getConnection = (id: string) => {
        return connections.find((c) => c.id === id);
    };

    const updateConnection = async (connectionId: string, attribute: string, newValue: string) => {
        if (!project) {
            return;
        }
        const updated = [...connections];
        const connection = updated.find((c) => c.id === connectionId);
        (connection as any)[attribute] = newValue;
        await getGitpodService().server.setProjectConnections(project.id, updated);
        updateConnections();
    };

    const toggleConnectionEnabled = async (id: string, newState: boolean) => {
        if (!project) {
            return;
        }
        let updated = [...connections];
        if (newState) {
            updated.push({ id });
        } else {
            updated = updated.filter((c) => c.id !== id);
        }
        await getGitpodService().server.setProjectConnections(project.id, updated);
        updateConnections();
    };

    return (
        <ProjectConnectionsPage project={project}>
            <h3>Projects Connections</h3>
            {getMockedConnectionTypes().map((type, i) => {
                const connection = getConnection(type.id);
                const attributes = type.attributes;
                return (
                    <>
                        <CheckBox
                            key={`type-${type}-${i}`}
                            title={
                                <span>
                                    Enable Tailscale{" "}
                                    <PillLabel type="warn" className="font-semibold mt-2 py-0.5 px-2 self-center">
                                        🚀
                                    </PillLabel>
                                </span>
                            }
                            desc={
                                <span>
                                    {!!connection &&
                                        attributes.map((attribute, i) => (
                                            <div className="mt-4" key={`attribute-${attribute}-${i}`}>
                                                <h4>{attribute}</h4>
                                                <input
                                                    className="w-full"
                                                    type="text"
                                                    name="value"
                                                    value={(connection as any)[attribute]}
                                                    onChange={(e) =>
                                                        updateConnection(connection.id, attribute, e.target.value)
                                                    }
                                                />
                                            </div>
                                        ))}
                                </span>
                            }
                            checked={!!connection}
                            onChange={() => toggleConnectionEnabled(type.id, !connection)}
                        />
                    </>
                );
            })}
        </ProjectConnectionsPage>
    );
}
