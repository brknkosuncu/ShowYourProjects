import React from "react";
import { useSelector} from "react-redux";
import Project from "./Project/Project";
import { Col } from "reactstrap";


const MyProjects = ({ setCurrentId }) => {
  const projects = useSelector((state) => state.projects);
  const user = JSON.parse(localStorage.getItem('profile'));
 
    return (
    <div>
      <Col md="8">
        
          {projects.map((project) => (

           (user?.result?.googleId === project?.creator || user?.result?._id === project?.creator) && (
          <Project project={project} setCurrentId={setCurrentId} key={project._id} />
          )

        ))}
         
        
      </Col>
    </div>
  );
};

export default MyProjects;
