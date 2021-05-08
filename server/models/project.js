import mongoose from "mongoose";

const projectSchema = mongoose.Schema({
  projectName: { type: String, required: true },
  groupName: { type: String, required: true },
  projectType: { type: String, required: true },
  creator: { type: String, required: true },
  name: { type: String, required: true },
  numOfDevelopers: { type: String, required: true },
  numOfRequirements: { type: String, required: true },
  image: { type: String },
  title: { type: String, required: true },
  description: String,
  gitHub: String,
  likes: {
    type: [String],
    default: [],
  },

  createdAt: {
    type: Date,
    default: new Date(),
  },
});

const Project = mongoose.model("Project", projectSchema);

export default Project;
